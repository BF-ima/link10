from django.urls import path, include
from .views import PersonneListCreateView, StartupListCreateView, BureauEtudeListView, LoginAPIView, ChatViewSet, MessageViewSet, PersonneProfileViewSet, StartupProfileViewSet, BureauEtudeProfileViewSet, FeedbackViewSet, RefreshTokenView 
from rest_framework.routers import DefaultRouter
from rest_framework_nested import routers
from .views import MemberSearchView, MemberManagementViewSet, BureauEtudeSearchView, BureauEtudeDetailView
from .views import (
    ConsultationTypeListView,
    ConsultationRequestViewSet,
    ConsultationRequestActionView,
    PaymentRequestViewSet
)



# Create a router for the main viewsets
router = DefaultRouter()
router.register(r'chats', ChatViewSet, basename='chat')
# Other router registrations...
router.register(r'personne-profiles', PersonneProfileViewSet, basename='personne-profile')
router.register(r'startup-profiles', StartupProfileViewSet, basename='startup-profile')
router.register(r'bureau-profiles', BureauEtudeProfileViewSet, basename='bureau-profile')

router.register(r'feedbacks', FeedbackViewSet, basename='feedback')

# Create a nested router for the messages within chats
chat_router = routers.NestedSimpleRouter(router, r'chats', lookup='chat')
chat_router.register(r'messages', MessageViewSet, basename='chat-messages')

chat_router.register(r'messages/(?P<message_id>[^/.]+)/mark_as_read', MessageViewSet, basename='mark_as_read')

urlpatterns = [
    path('login', LoginAPIView.as_view()),
    path('refresh/', RefreshTokenView.as_view(), name='token_refresh'),
    path('personne/', PersonneListCreateView.as_view(), name='personne_list_create'),
    path('startup/', StartupListCreateView.as_view(), name='startup_list_create'),
    path('bureau/', BureauEtudeListView.as_view(), name='bureau_etude_list'),
    path('', include(router.urls)),
    path('', include(chat_router.urls)),
    path('members/search/', MemberSearchView.as_view(), name='member-search'),
    path('members/', include(router.urls)),  # For member management
    path('bureau/search/', BureauEtudeSearchView.as_view(), name='bureau-search'),
    path('bureau/<int:pk>/', BureauEtudeDetailView.as_view(), name='bureau-detail'),
      path('consultation-types/', ConsultationTypeListView.as_view(), name='consultation-types'),
    path('consultation-requests/<int:pk>/<str:action>/', ConsultationRequestActionView.as_view(), name='consultation-action'),
  ]

# Register the member management viewset
router.register(r'members', MemberManagementViewSet, basename='member-management')   
router.register(r'consultation-requests', ConsultationRequestViewSet, basename='consultation-request')
router.register(r'payment-requests', PaymentRequestViewSet, basename='payment-request')
    

