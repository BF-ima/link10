from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import api_view
from .serializers import PersonneSerializer, StartupSerializer, BureauEtudeSerializer, RegisterStartupSerializer, RegisterSerializer, ChatSerializer, MessageSerializer, PersonneProfileSerializer, StartupProfileSerializer, BureauEtudeProfileSerializer, FeedbackSerializer, MessageAttachmentSerializer 
from rest_framework.permissions import AllowAny
from rest_framework import generics
from rest_framework.views import APIView
from rest_framework.exceptions import APIException, AuthenticationFailed
from .authentication import create_access_token, create_refresh_token
from rest_framework import viewsets, permissions, status, filters
from rest_framework.decorators import action
from django.db.models import Q, Max, Count, OuterRef, Subquery
from django.utils import timezone
from django.shortcuts import get_object_or_404
from .models import (
    Chat, Message, Personne, Startup, BureauEtude,
    PersonneProfile, StartupProfile, BureauEtudeProfile,
    MessageAttachment, StartupMember, ConsultationRequest, PaymentRequest, Feedback
)
from .models import ConsultationType
from .permissions import IsOwnerOrReadOnly, IsStartupOrPersonne
import jwt, datetime

class RefreshTokenView(APIView):
    def post(self, request):
        refresh_token = request.COOKIES.get('refreshToken')

        if not refresh_token:
            raise AuthenticationFailed('No refresh token provided')

        try:
            payload = jwt.decode(refresh_token, 'refresh_secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Refresh token expired')
        except jwt.InvalidTokenError:
            raise AuthenticationFailed('Invalid refresh token')

        access_token = create_access_token(payload['user_id'], payload['name'])

        return Response({'token': access_token})

from .serializers import ConsultationTypeSerializer
from .serializers import ConsultationRequestCreateSerializer
from .serializers import ConsultationRequestSerializer
from .serializers import PaymentRequestSerializer
from .serializers import StartupProfileUpdateSerializer

class ConsultationTypeListView(generics.ListAPIView):
    queryset = ConsultationType.objects.all()
    serializer_class = ConsultationTypeSerializer
    permission_classes = [permissions.IsAuthenticated]

class ConsultationRequestViewSet(viewsets.ModelViewSet):
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'startupprofile'):
            return ConsultationRequest.objects.filter(startup=user.startupprofile.startup)
        elif hasattr(user, 'bureauetudeprofile'):
            return ConsultationRequest.objects.filter(bureau=user.bureauetudeprofile.bureau)
        return ConsultationRequest.objects.none()
    
    def get_serializer_class(self):
        if self.action == 'create':
            return ConsultationRequestCreateSerializer
        return ConsultationRequestSerializer
    
    def perform_create(self, serializer):
        if hasattr(self.request.user, 'startupprofile'):
            bureau_id = self.request.data.get('bureau_id')
            bureau = get_object_or_404(BureauEtude, id_bureau=bureau_id)
            serializer.save(
                startup=self.request.user.startupprofile.startup,
                bureau=bureau,
                status='pending'
            )
        else:
            raise PermissionDenied("Only startups can create consultation requests")

class ConsultationRequestActionView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request, pk, action):
        consultation = get_object_or_404(ConsultationRequest, pk=pk)
        
        # Check if user is the bureau owner
        if not hasattr(request.user, 'bureauetudeprofile') or consultation.bureau != request.user.bureauetudeprofile.bureau:
            raise PermissionDenied("You don't have permission to perform this action")
        
        if action == 'accept':
            consultation.status = 'accepted'
            consultation.save()
            
            # Create payment request
            payment_request = PaymentRequest.objects.create(
                consultation=consultation,
                amount=10000,  # Default amount or get from consultation type
                payment_method='Baird Mob'
            )
            
            # Create notification for startup
            # You'll need to implement your notification system here
            
            return Response({
                'status': 'consultation accepted',
                'payment_request': PaymentRequestSerializer(payment_request).data
            })
            
        elif action == 'reject':
            consultation.status = 'rejected'
            consultation.save()
            
            # Create notification for startup
            return Response({'status': 'consultation rejected'})
        
        return Response(
            {'error': 'Invalid action'},
            status=status.HTTP_400_BAD_REQUEST
        )

class PaymentRequestViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = PaymentRequestSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'startupprofile'):
            return PaymentRequest.objects.filter(consultation__startup=user.startupprofile.startup)
        elif hasattr(user, 'bureauetudeprofile'):
            return PaymentRequest.objects.filter(consultation__bureau=user.bureauetudeprofile.bureau)
        return PaymentRequest.objects.none()
    


class BureauEtudeSearchView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        query = request.query_params.get('q', '')
        specialization = request.query_params.get('specialization', '')
        
        bureaus = BureauEtude.objects.all()
        
        if query:
            bureaus = bureaus.filter(
                Q(nom__icontains=query) |
                Q(description__icontains=query)
            )
        
        if specialization:
            bureaus = bureaus.filter(description__icontains=specialization)
        
        serializer = BureauEtudeSerializer(bureaus, many=True)
        return Response(serializer.data)

class BureauEtudeDetailView(generics.RetrieveAPIView):
    queryset = BureauEtude.objects.all()
    serializer_class = BureauEtudeSerializer
    permission_classes = [permissions.IsAuthenticated]


class MemberSearchView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        query = request.query_params.get('q', '')
        
        # Ensure the user is a startup
        if not hasattr(request.user, 'startupprofile'):
            return Response(
                {'error': 'Only startups can search members'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Search in current members
        current_members = request.user.startupprofile.members.filter(
            Q(nom__icontains=query) | 
            Q(email__icontains=query)
        ).distinct()
        
        # Search in potential members (users not in the startup)
        potential_members = Personne.objects.filter(
            Q(nom__icontains=query) | 
            Q(email__icontains=query)
        ).exclude(id_personne__in=current_members.values_list('id_personne', flat=True)).distinct()
        
        current_members_data = PersonneSerializer(current_members, many=True).data
        potential_members_data = PersonneSerializer(potential_members, many=True).data
        
        return Response({
            'current_members': current_members_data,
            'potential_members': potential_members_data
        })


class MemberManagementViewSet(viewsets.ViewSet):
    permission_classes = [permissions.IsAuthenticated]

    @action(detail=False, methods=['post'])
    def add_member(self, request):
        # Check if user is a startup
        if not hasattr(request.user, 'startupprofile'):
            return Response(
                {'error': 'Only startups can add members'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        member_id = request.data.get('member_id')
        if not member_id:
            return Response(
                {'error': 'member_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            member = Personne.objects.get(id_personne=member_id)
            request.user.startupprofile.members.add(member)
            return Response({'status': 'member added'})
        except Personne.DoesNotExist:
            return Response(
                {'error': 'Member not found'},
                status=status.HTTP_404_NOT_FOUND
            )

    @action(detail=True, methods=['delete'])
    def remove_member(self, request, pk=None):
        # Check if user is a startup
        if not hasattr(request.user, 'startupprofile'):
            return Response(
                {'error': 'Only startups can remove members'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        try:
            member = Personne.objects.get(id_personne=pk)
            request.user.startupprofile.members.remove(member)
            return Response({'status': 'member removed'})
        except Personne.DoesNotExist:
            return Response(
                {'error': 'Member not found'},
                status=status.HTTP_404_NOT_FOUND
            )



class FeedbackViewSet(viewsets.ModelViewSet):
    serializer_class = FeedbackSerializer
    permission_classes = [permissions.IsAuthenticated, IsStartupOrPersonne]


    def get_queryset(self):
        # Allow all logged-in users to see all feedbacks
        return Feedback.objects.all()

    def perform_create(self, serializer):
        user = self.request.user

        bureau = None
        startup = None
        personne = None

        # Determine which user type is sending the feedback
        if hasattr(user, 'startupprofile'):
            startup = user.startupprofile.startup
        elif hasattr(user, 'personneprofile'):
            personne = user.personneprofile.personne

        # Assume feedback is for a specific bureau, passed via request data
        bureau_id = self.request.data.get('bureau_id')
        bureau = BureauEtude.objects.get(id=bureau_id)

        serializer.save(bureau=bureau, startup=startup, personne=personne)


class PersonneProfileViewSet(viewsets.ModelViewSet):
    serializer_class = PersonneProfileSerializer
    queryset = PersonneProfile.objects.all()
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrReadOnly]

    def perform_create(self, serializer):
        serializer.save(personne=self.request.user)


class StartupProfileViewSet(viewsets.ModelViewSet):
    serializer_class = StartupProfileSerializer
    queryset = StartupProfile.objects.all()
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrReadOnly]

    def perform_create(self, serializer):
        serializer.save(startup=self.request.user)

    def get_serializer_class(self):
        if self.action in ['update', 'partial_update']:
            return StartupProfileUpdateSerializer
        return self.serializer_class


class BureauEtudeProfileViewSet(viewsets.ModelViewSet):
    serializer_class = BureauEtudeProfileSerializer
    queryset = BureauEtudeProfile.objects.all()
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrReadOnly]

    def perform_create(self, serializer):
        serializer.save(bureau=self.request.user)


class ChatViewSet(viewsets.ModelViewSet):
    queryset = Chat.objects.all()
    serializer_class = ChatSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        user = self.request.user
        
        # Determine which chats to fetch based on user type
        if hasattr(user, 'id_bureau'):
            return Chat.objects.filter(bureau=user)
        elif hasattr(user, 'id_startup'):
            return Chat.objects.filter(startup=user)
        elif hasattr(user, 'id_personne'):
            return Chat.objects.filter(personne=user)    
        return Chat.objects.none()
    

    @action(detail=False, methods=['post'])
    def create_or_get(self, request):
        bureau_id = request.data.get('bureau_id')
        startup_id = request.data.get('startup_id')
        personne_id = request.data.get('personne_id')

        if not startup_id:
            return Response(
                {'error': 'startup_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        # Check that either bureau or personne is provided, but not both
        if (bureau_id and personne_id) or (not bureau_id and not personne_id):
            return Response(
                {'error': 'Exactly one of bureau_id or personne_id must be provided'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Construct filter criteria for existing chat lookup
        filter_kwargs = {'startup_id': startup_id}
        if bureau_id:
            filter_kwargs['bureau_id'] = bureau_id
        elif personne_id:
            filter_kwargs['personne_id'] = personne_id


        # Check if chat already exists
        try:
            chat = Chat.objects.get(**filter_kwargs)
            serializer = self.get_serializer(chat)
            return Response(serializer.data)
        except Chat.DoesNotExist:
            # Create a new chat with the data
            data = {
                'startup': startup_id,
                'is_active': True
            }
            
            # Add either bureau or personne
            if bureau_id:
                data['bureau'] = bureau_id
            elif personne_id:
                data['personne'] = personne_id
                
            serializer = self.get_serializer(data=data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)


class MessageViewSet(viewsets.ModelViewSet):
    queryset = Message.objects.all()
    serializer_class = MessageSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        chat_id = self.kwargs.get('chat_pk') or self.request.query_params.get('chat_id')
        user = self.request.user
        if not chat_id:
            return Message.objects.none()

        queryset = Message.objects.filter(chat_id=chat_id).order_by('timestamp')

        # Automatically mark unread messages as read
        if hasattr(user, 'id_bureau'):
            receiver_type = Message.BUREAU
            receiver_id = user.id_bureau
        elif hasattr(user, 'id_startup'):
            receiver_type = Message.STARTUP
            receiver_id = user.id_startup
        elif hasattr(user, 'id_personne'):
            receiver_type = Message.PERSONNE
            receiver_id = user.id_personne
        else:
            return queryset  # unknown user, don't touch

        unread_messages = queryset.filter(
            receiver_type=receiver_type,
            receiver_id=receiver_id,
            is_read=False
        )

        now = timezone.now()
        unread_messages.update(is_read=True, read_at=now)

        return queryset

             
    
    def create(self, request, *args, **kwargs):
        chat_id = request.data.get('chat_id')
        user = request.user
        
        # Determine sender type and ID based on user
        if hasattr(user, 'id_bureau'):
            sender_type = Message.BUREAU
            sender_id = user.id_bureau
        elif hasattr(user, 'id_startup'):
            sender_type = Message.STARTUP
            sender_id = user.id_startup
        elif hasattr(user, 'id_personne'):
            sender_type = Message.PERSONNE
            sender_id = user.id_personne
        else:
            return Response(
                {'error': 'Unknown user type'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        # Get the chat to determine receiver info
        try:
            chat = Chat.objects.get(id=chat_id)
        except Chat.DoesNotExist:
            return Response(
                {'error': 'Chat does not exist'},
                status=status.HTTP_404_NOT_FOUND
            )
            
        # Determine receiver type and ID based on sender and chat
        if sender_type == Message.STARTUP:
            if chat.bureau:
                receiver_type = Message.BUREAU
                receiver_id = chat.bureau.id
            elif chat.personne:
                receiver_type = Message.PERSONNE
                receiver_id = chat.personne.id
            else:
                return Response(
                    {'error': 'Chat has no valid receiver'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        elif sender_type == Message.BUREAU and chat.startup:
            receiver_type = Message.STARTUP
            receiver_id = chat.startup.id
        elif sender_type == Message.PERSONNE and chat.startup:
            receiver_type = Message.STARTUP
            receiver_id = chat.startup.id
        else:
            return Response(
                {'error': 'Invalid sender or receiver configuration'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Update request data with sender and receiver info
        data = request.data.copy()
        data.update({
            'chat': chat_id,
            'sender_type': sender_type,
            'sender_id': sender_id,
            'receiver_type': receiver_type,
            'receiver_id': receiver_id
        })
        
        # Handle file uploads if present
        if 'file' in request.FILES:
            file_obj = request.FILES['file']
            # Determine content type based on file
            mime_type = file_obj.content_type
            if mime_type.startswith('image/'):
                data['content_type'] = Message.IMAGE
            elif mime_type.startswith('video/'):
                data['content_type'] = Message.VIDEO
            elif mime_type.startswith('audio/'):
                data['content_type'] = Message.AUDIO
            else:
                data['content_type'] = Message.FILE
                
            data['media_file'] = file_obj
        else:
            # Default to text message
            data['content_type'] = Message.TEXT
            
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        message = serializer.save()
        
        # Update the chat's last_message_at timestamp
        chat.last_message_at = timezone.now()
        chat.save(update_fields=['last_message_at'])
        
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    
    @action(detail=True, methods=['post'])
    def mark_as_read(self, request, pk=None, chat_pk=None):
        message = self.get_object()
        message.mark_as_read()
        return Response({'status': 'message marked as read'})
    
    @action(detail=False, methods=['post'])
    def mark_all_as_read(self, request):
        chat_id = request.data.get('chat_id')
        if not chat_id:
            return Response(
                {'error': 'chat_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get current user type and ID
        user = request.user
        if hasattr(user, 'id_bureau'):
            receiver_type = 'bureau'
            receiver_id = user.id_bureau
        elif hasattr(user, 'id_startup'):
            receiver_type = 'startup'
            receiver_id = user.id_startup
        elif hasattr(user, 'id_personne'):
            receiver_type = Message.PERSONNE
            receiver_id = user.id_personne    
        else:
            return Response(
                {'error': 'Unknown user type'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Mark all unread messages as read
        now = timezone.now()
        updated = Message.objects.filter(
            chat_id=chat_id,
            receiver_type=receiver_type,
            receiver_id=receiver_id,
            is_read=False
        ).update(is_read=True, read_at=now)
        
        return Response({'status': f'{updated} messages marked as read'})


class MessageAttachmentViewSet(viewsets.ModelViewSet):
    queryset = MessageAttachment.objects.all()
    serializer_class = MessageAttachmentSerializer  
    permission_classes = [permissions.IsAuthenticated]
    
    def create(self, request, *args, **kwargs):
        message_id = request.data.get('message_id')
        if not message_id:
            return Response(
                {'error': 'message_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        # Validate that the message exists
        try:
            message = Message.objects.get(id=message_id)
        except Message.DoesNotExist:
            return Response(
                {'error': 'Message does not exist'},
                status=status.HTTP_404_NOT_FOUND
            )
            
        # Process each uploaded file
        files = request.FILES.getlist('files')
        if not files:
            return Response(
                {'error': 'No files provided'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        attachments = []
        for file in files:
            attachment_data = {
                'message': message_id,
                'file': file,
                'file_name': file.name,
                'file_size': file.size,
                'file_type': file.content_type
            }
            
            serializer = self.get_serializer(data=attachment_data)
            serializer.is_valid(raise_exception=True)
            attachment = serializer.save()
            attachments.append(serializer.data)
            
        return Response(attachments, status=status.HTTP_201_CREATED)    


class LoginAPIView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            raise APIException('Email and password are required!')

        user = None
        t = None

        for model in [Startup, Personne, BureauEtude]:
            user = model.objects.filter(email=email).first()
            if user:
                if model==Personne:
                    t=user.id_personne
                elif model==Startup:
                    t=user.id_startup
                else:
                    t=user.id_bureau        
                break

        if not user:
            raise APIException('Invalid credentials!')
     
        elif not user.check_password(request.data['password']): #not check_password(password, user.password):
            raise APIException('Invalid password!')

        access_token = create_access_token(t, user.nom)
        refresh_token = create_refresh_token(t, user.nom)

        response = Response()
        response.set_cookie(key='refreshToken', value=refresh_token, httponly=True) 
        response.data = {
            'token': access_token,
        }

        return response

     

# For creating and listing Personne objects
class PersonneListCreateView(generics.ListCreateAPIView):
    queryset = Personne.objects.all()
    serializer_class = RegisterSerializer

# For creating and listing Startup objects
class StartupListCreateView(generics.ListCreateAPIView):
    queryset = Startup.objects.all()
    serializer_class = RegisterStartupSerializer

# For listing BureauEtude objects (assuming no POST method here)
class BureauEtudeListView(generics.ListAPIView):
    queryset = BureauEtude.objects.all()
    serializer_class = BureauEtudeSerializer

@api_view(['GET', 'POST'])
def personne_view(request):
    if request.method == 'GET':
        personnes = Personne.objects.all()
        serializer = PersonneSerializer(personnes, many=True)
        return Response(serializer.data)

    elif request.method == 'POST':
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'POST'])
def startup_view(request):
    if request.method == 'GET':
        startups = Startup.objects.all()
        serializer = StartupSerializer(startups, many=True)
        return Response(serializer.data)

    elif request.method == 'POST':
        serializer = RegisterStartupSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
def bureau_etude_view(request):
    if request.method == 'GET':
        bureau_etudes = BureauEtude.objects.all()
        serializer = BureauEtudeSerializer(bureau_etudes, many=True)
        return Response(serializer.data)

