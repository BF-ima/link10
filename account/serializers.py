from rest_framework import serializers
from .models import Personne, Startup, BureauEtude, PersonneProfile, StartupProfile, BureauEtudeProfile, Chat, Message, MessageAttachment, Feedback
from django.contrib.auth.password_validation import validate_password 
from rest_framework.exceptions import ValidationError
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate
from django.contrib.auth.backends import ModelBackend
from django.utils import timezone
from .models import ConsultationType
from .models import ConsultationRequest
from .models import PaymentRequest


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = Personne
        fields = [
            'nom', 'genre', 'adresse', 'numero_telephone', 'email',
            'wilaya', 'date_naissance', 'titre_role', 'description_role', 'password2', 'password'
        ]  # Removed 'id_startup'
    
    def validate(self, attrs):
        # Validate that password and password2 match
        if attrs['password'] != attrs['password2']:
            raise ValidationError({"password": "Password fields didn't match."})
        if len(attrs['numero_telephone']) != 10:
            raise ValidationError({"numero_telephone": "Phone number must be 10 digits."})    
        return attrs
       
    def create(self, validated_data):
        validated_data.pop('password2')  # Remove 'password2' since it's not part of the model
        personne = Personne.objects.create_user(**validated_data)  # ✅ Create the user first

        PersonneProfile.objects.create(personne=personne)  # ✅ Now use the created instance

        return personne


class RegisterStartupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)
    password2 = serializers.CharField(write_only=True, required=True)  # 🔹 Ensure password is not exposed

    class Meta:
        model = Startup
        fields = ['genre_leader', 'nom_leader', 'date_naissance_leader','nom', 'adresse', 'numero_telephone', 'email', 'wilaya', 'description', 'date_creation', 'secteur', 'password2', 'password'] # Excludes 'id_startup'
    
    def validate(self, attrs):
        # Validate that password and password2 match
        if attrs['password'] != attrs['password2']:
            raise ValidationError({"password": "Password fields didn't match."})
        if len(attrs['numero_telephone']) != 10:
            raise ValidationError({"numero_telephone": "Phone number must be 10 digits."})    
        return attrs

    def create(self, validated_data):
        validated_data.pop('password2')
        validated_data['password'] = make_password(validated_data['password'])  # 🔹 Hash password

        
        startup = Startup.objects.create(**validated_data)  # ✅ Create startup first

        StartupProfile.objects.create(startup=startup)

        return startup



class PersonneSerializer(serializers.ModelSerializer):
    class Meta:
        model = Personne
        fields = ['nom', 'genre', 'adresse', 'numero_telephone', 'email', 'wilaya', 'date_naissance', 'titre_role', 'description_role']
        read_only_fields = ['id_personne']

class StartupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Startup
        fields = ['genre_leader', 'nom_leader', 'date_naissance_leader','nom', 'adresse', 'numero_telephone', 'email', 'wilaya', 'description', 'date_creation', 'secteur']
        read_only_fields = ['id_startup']


class BureauEtudeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Startup
        fields = ['nom', 'adresse', 'numero_telephone', 'email', 'wilaya', 'description', 'date_creation']
        read_only_fields = ['id_bureau']  

class FeedbackSerializer(serializers.ModelSerializer):
    class Meta:
        model = Feedback
        fields = ['id', 'bureau', 'startup', 'personne', 'comment', 'rating', 'created_at']


class PersonneProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = PersonneProfile
        fields = '__all__'

class BureauEtudeProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = BureauEtudeProfile
        fields = '__all__'

class StartupProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = StartupProfile
        fields = '__all__'

   # Both the sender and the receiver can see the attachments — but only the sender uses uploaded_files to upload them
# Correct indentation and file validation inside the proper serializer
class MessageAttachmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = MessageAttachment
        fields = ['id', 'file', 'file_name', 'file_size', 'file_type', 'created_at']
        read_only_fields = ['id', 'created_at']

# Inside the MessageSerializer class (assuming it's here where the uploaded files are processed)
class MessageSerializer(serializers.ModelSerializer):
    attachments = MessageAttachmentSerializer(many=True, read_only=True)
    uploaded_files = serializers.ListField(
        child=serializers.FileField(max_length=100000, allow_empty_file=False),
        write_only=True,
        required=False
    )
    
    class Meta:
        model = Message
        fields = [
            'id', 'chat', 'sender_type', 'sender_id', 
            'receiver_type', 'receiver_id', 'content_type',
            'text_content', 'media_file', 'timestamp', 
            'is_read', 'read_at', 'attachments', 'uploaded_files'
        ]
        read_only_fields = ['id', 'timestamp', 'is_read', 'read_at']
    
    # ✅ Validation for uploaded files
    def validate_uploaded_files(self, value):
        max_size = 5 * 1024 * 1024  # 5 MB limit
        for file in value:
            if file.size > max_size:
                raise serializers.ValidationError(f"The file '{file.name}' exceeds the maximum size of 5MB.")
        return value

    def create(self, validated_data):
        uploaded_files = validated_data.pop('uploaded_files', None)
        
        # Create the message
        message = Message.objects.create(**validated_data)
        
        # Process any attachments
        if uploaded_files:
            for file in uploaded_files:
                MessageAttachment.objects.create(
                    message=message,
                    file=file,
                    file_name=file.name,
                    file_size=file.size,
                    file_type=file.content_type
                )
        
        # Update the chat's last_message_at timestamp
        message.chat.last_message_at = timezone.now()
        message.chat.save(update_fields=['last_message_at'])
        
        return message


class ChatSerializer(serializers.ModelSerializer):
    last_message = serializers.SerializerMethodField()
    unread_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Chat
        fields = [
            'id', 'bureau', 'startup', 'personne', 'created_at', 
            'updated_at', 'last_message_at', 'is_active',
            'last_message', 'unread_count'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'last_message_at']
    
    def get_last_message(self, obj):
        last_message = obj.messages.order_by('-timestamp').first()
        if last_message:
            return {
                'id': last_message.id,
                'content_type': last_message.content_type,
                'text_content': last_message.text_content if last_message.content_type == 'text' else None,
                'sender_type': last_message.sender_type,
                'timestamp': last_message.timestamp,
            }
        return None
    
    def get_unread_count(self, obj):
        # Get the current user from the context
        user = self.context.get('request').user if self.context.get('request') else None
        if not user:
            return 0
        
        # Determine the entity type
        if hasattr(user, 'id_startup'):
            entity_type = 'startup'
            entity_id = user.id_startup
        elif hasattr(user, 'id_bureau'):
            entity_type = 'bureau'
            entity_id = user.id_bureau
        elif hasattr(user, 'id_personne'):  
            entity_type = 'personne'
            entity_id = user.id_personne    
        else:
            return 0
        
        # Count unread messages for this user in this chat
        return obj.messages.filter(
            receiver_type=entity_type,
            receiver_id=entity_id,
            is_read=False
        ).count()


class StartupProfileUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = StartupProfile
        fields = [
            'logo', 'owner_name', 'phone', 'email', 'location',
            'industry', 'description', 'website', 'date_creation',
            'facebook', 'linkedin', 'whatsapp',
            'leader_first_name', 'leader_last_name', 'leader_date_of_birth',
            'leader_gender', 'leader_bio', 'leader_phone', 'leader_email',
            'leader_location', 'leader_facebook', 'leader_linkedin', 'leader_whatsapp'
        ]
        extra_kwargs = {
            'email': {'required': False},
            'leader_email': {'required': False}
        }


class ConsultationTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = ConsultationType
        fields = '__all__'

class ConsultationRequestSerializer(serializers.ModelSerializer):
    bureau = BureauEtudeSerializer(read_only=True)
    startup = StartupSerializer(read_only=True)
    consultation_type = ConsultationTypeSerializer(read_only=True)
    
    class Meta:
        model = ConsultationRequest
        fields = '__all__'
        read_only_fields = ('status', 'created_at', 'updated_at')

class ConsultationRequestCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = ConsultationRequest
        fields = ('consultation_type', 'problem_description')
        
    def validate(self, data):
        if not data.get('consultation_type'):
            raise serializers.ValidationError("Consultation type is required")
        if not data.get('problem_description'):
            raise serializers.ValidationError("Problem description is required")
        return data

class PaymentRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = PaymentRequest
        fields = '__all__'
        read_only_fields = ('is_paid', 'created_at')
