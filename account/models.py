from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.utils import timezone
import uuid
import os

# Create your models here.

class PersonneManager(BaseUserManager):
    def create_user(self, email, nom, numero_telephone, genre, adresse, wilaya, date_naissance, titre_role, description_role,  password):
        if not email:
            raise ValueError('The Email field must be set')
        user = self.model(
            email=self.normalize_email(email),
            nom=nom,
            numero_telephone=numero_telephone,
            genre=genre,
            adresse=adresse,
            wilaya=wilaya,
            date_naissance=date_naissance,
            titre_role=titre_role,
            description_role=description_role,
        )
        user.set_password(password)
        user.save(using=self._db)
        return user


class StartupManager(BaseUserManager):
    def create_user(self, genre_leader, nom_leader, date_naissance_leader, nom, adresse, numero_telephone, email, wilaya, description, date_creation, secteur, password):
        if not email:
            raise ValueError('The Email field must be set')
        user = self.model(
            email=self.normalize_email(email),
            nom_leader=nom_leader,
            genre_leader=genre_leader,
            date_naissance_leader=date_naissance_leader,
            nom=nom,
            numero_telephone=numero_telephone,
            adresse=adresse,
            wilaya=wilaya,
            date_creation=date_creation,
            description=description,
            secteur=secteur,
        )
        user.set_password(password)
        user.save(using=self._db)
        return user


class Personne(AbstractBaseUser):

    HOMME = 'Homme'
    FEMME = 'Femme'

    GENDER_CHOICES = [
        (HOMME, 'Homme'),
        (FEMME, 'Femme'),
    ]

    nom = models.CharField(max_length=255)
    genre = models.CharField(max_length=50, choices=GENDER_CHOICES)
    is_active = models.BooleanField(default=True)
    id_personne = models.AutoField(primary_key=True)
    adresse = models.TextField()
    numero_telephone = models.CharField(max_length=10, unique=True)
    email = models.EmailField(unique=True)
    wilaya = models.CharField(max_length=100)
    date_naissance = models.DateField()
    titre_role = models.CharField(max_length=100)
    description_role = models.TextField()
    startups = models.ManyToManyField('Startup', through='StartupMember', related_name='personne_startups') 

    USERNAME_FIELD = "email"
    objects = PersonneManager()


    class Meta:
        db_table = 'personne'
        managed = True   


    def __str__(self):
        return self.email


class BureauEtude(AbstractBaseUser):
    id_bureau = models.AutoField(primary_key=True)
    date_creation = models.DateField(verbose_name="Date de création")
    nom = models.CharField(max_length=255, verbose_name="Nom")
    numero_telephone = models.CharField(max_length=10, verbose_name="Numéro de téléphone")
    email = models.EmailField(unique=True, verbose_name="Email")
    adresse = models.TextField(verbose_name="Adresse")
    wilaya = models.CharField(max_length=100, verbose_name="Wilaya")
    description = models.TextField(blank=True, null=True, verbose_name="Description")

    USERNAME_FIELD = "email"
    
    def __str__(self):
        return self.nom

class Startup(AbstractBaseUser):
    HOMME = 'Homme'
    FEMME = 'Femme'

    GENDER_CHOICES = [
        (HOMME, 'Homme'),
        (FEMME, 'Femme'),
    ]
    nom_leader = models.CharField(max_length=255)  
    genre_leader = models.CharField(max_length=50, choices=GENDER_CHOICES)  
    date_naissance_leader = models.DateField()
    id_startup = models.AutoField(primary_key=True)
    date_creation = models.DateField(verbose_name="Date de création")
    description = models.TextField(verbose_name="Description")
    nom = models.CharField(max_length=255, verbose_name="Nom")
    is_active = models.BooleanField(default=True)
    adresse = models.TextField(verbose_name="Adresse", blank=True)
    wilaya = models.CharField(max_length=100, verbose_name="Wilaya")
    email = models.EmailField(unique=True, verbose_name="Email")
    numero_telephone = models.CharField(max_length=10, verbose_name="Numéro de téléphone")
    TYPE_S = [
        ('Tech', 'Technologie'),
        ('Health', 'Santé'),
        ('Finance', 'Finance'),
    ]
    secteur = models.CharField(max_length=50, choices=TYPE_S, verbose_name="Secteur d'activité")
    # Added many-to-many relationship with Personne as members
    members = models.ManyToManyField(Personne, through='StartupMember', related_name='startup_members')      

    USERNAME_FIELD = "email"
    objects = StartupManager()

    class Meta:
        db_table = "startup"  # Define custom table name
        managed = True  # Ensure Django manages this model
   

    def __str__(self):
        return self.email    

class StartupMember(models.Model):
    # Through model for the many-to-many relationship between Startup and Personne
    startup = models.ForeignKey(Startup, on_delete=models.CASCADE)
    personne = models.ForeignKey(Personne, on_delete=models.CASCADE)
    date_joined = models.DateField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    role = models.CharField(max_length=100, blank=True, null=True)  # Role within the startup

    class Meta:
        unique_together = ('startup', 'personne')  # A person can only be a member of a startup once

    def __str__(self):
        return f"{self.personne.nom} - {self.startup.nom}"


class Feedback(models.Model):
    bureau = models.ForeignKey(BureauEtude, on_delete=models.CASCADE)
    startup = models.ForeignKey(Startup, on_delete=models.CASCADE, null=True, blank=True)
    personne = models.ForeignKey(Personne, on_delete=models.CASCADE, null=True, blank=True)
    
    comment = models.TextField()
    rating = models.IntegerField(choices=[(i, str(i)) for i in range(1, 6)])  # 1 to 5 stars
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Feedback ({self.rating}★) from {self.startup or self.personne} to {self.bureau}"
       

class PersonneProfile(models.Model):
    personne = models.OneToOneField(Personne, on_delete=models.CASCADE, related_name='profile')

    avatar = models.ImageField(upload_to='personne_avatars/', blank=True, null=True)
    
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    
    date_of_birth = models.DateField()
    gender = models.CharField(max_length=10, choices=[("Male", "Male"), ("Female", "Female")])
    
    bio = models.TextField(blank=True, null=True)  # e.g., "Co-CEO of Startup"

    phone = models.CharField(max_length=20)

    email = models.EmailField()
    location = models.CharField(max_length=255)

    facebook = models.URLField(blank=True, null=True)
    linkedin = models.URLField(blank=True, null=True)
    whatsapp = models.CharField(max_length=20, blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    startups = models.ManyToManyField('Startup', related_name='memberss')

    def __str__(self):
        return f"{self.first_name} {self.last_name} Profile"               

class BureauEtudeProfile(models.Model):
    bureau = models.OneToOneField(BureauEtude, on_delete=models.CASCADE, related_name='profile')

    avatar = models.ImageField(upload_to='bureau_avatars/', blank=True, null=True)
    bio = models.TextField(blank=True, null=True, help_text="Short description or role (e.g., CEO of ConsultingName)")

    phone = models.CharField(max_length=20, blank=True, null=True)
    email = models.EmailField(blank=True, null=True)
    location = models.CharField(max_length=255)

    date_creation = models.DateField(null=True)

    facebook = models.URLField(blank=True, null=True)
    linkedin = models.URLField(blank=True, null=True)
    whatsapp = models.CharField(max_length=20, blank=True, null=True)

    website = models.URLField(blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    

    def __str__(self):
        return f"Profile of {self.bureau.nom}"

class StartupProfile(models.Model):
    startup = models.OneToOneField(Startup, on_delete=models.CASCADE, related_name='profile')

    ## leader info 

    leader_avatar = models.ImageField(upload_to='personne_avatars/', blank=True, null=True)
    
    leader_first_name = models.CharField(max_length=100)
    leader_last_name = models.CharField(max_length=100)
    
    leader_date_of_birth = models.DateField()
    leader_gender = models.CharField(max_length=10, choices=[("Male", "Male"), ("Female", "Female")])
    
    leader_bio = models.TextField(blank=True, null=True)  # e.g., "Co-CEO of Startup"

    leader_phone = models.CharField(max_length=20)

    leader_email = models.EmailField()
    leader_location = models.CharField(max_length=255)

    leader_facebook = models.URLField(blank=True, null=True)
    leader_linkedin = models.URLField(blank=True, null=True)
    leader_whatsapp = models.CharField(max_length=20, blank=True, null=True)

    
    ## startup info 

    logo = models.ImageField(upload_to='startup_logos', blank=True, null=True)
    owner_name = models.CharField(max_length=100)  # "Owned by Fatima Ben Ali"
    
    phone = models.CharField(max_length=10)

    email = models.EmailField()
    location = models.CharField(max_length=255)  # e.g., "Algeria, Sidi Bel Abbes"

    industry = models.CharField(max_length=100)
    description = models.TextField()

    website = models.URLField(blank=True, null=True)
    
    date_creation = models.DateField(null=True)

    facebook = models.URLField(blank=True, null=True)
    linkedin = models.URLField(blank=True, null=True)
    whatsapp = models.CharField(max_length=20, blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    #  memebers of the startup

    members = models.ManyToManyField('Personne', related_name='startupss')

    def __str__(self):
        return f"Profile of {self.startup.name}"  


class Chat(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    bureau = models.ForeignKey(BureauEtude, on_delete=models.CASCADE, related_name='chats', null=True, blank=True)
    startup = models.ForeignKey(Startup, on_delete=models.CASCADE, related_name='chats')
    personne = models.ForeignKey(Personne, on_delete=models.CASCADE, related_name='chats', null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_message_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                check=(
                    models.Q(bureau__isnull=False, personne__isnull=True) |
                    models.Q(bureau__isnull=True, personne__isnull=False)
                ),
                name="only_one_receiver"
            ),
            models.UniqueConstraint(
                fields=['startup', 'bureau'],             # only one chat between two specific pair 
                condition=models.Q(bureau__isnull=False),
                name='unique_startup_bureau_chat'
            ),
            models.UniqueConstraint(
                fields=['startup', 'personne'],
                condition=models.Q(personne__isnull=False),
                name='unique_startup_personne_chat'
            ),
        ]

    def __str__(self):
        if self.bureau:
            return f"Chat between {self.startup.nom} and Bureau {self.bureau.nom}"
        elif self.personne:
            return f"Chat between {self.startup.nom} and Personne {self.personne.nom}"
        return f"Chat for {self.startup.nom}"


def message_file_path(instance, filename):
    """Generate a structured file path for each message attachment."""
    ext = filename.split('.')[-1]
    filename = f"{uuid4()}.{ext}"  # Generates a unique file name
    return os.path.join('messages', str(instance.chat.id), filename)

class Message(models.Model):
    # Updated Message model to support different content types
    TEXT = 'text'
    IMAGE = 'image'
    VIDEO = 'video'
    FILE = 'file'
    AUDIO = 'audio'
    
    CONTENT_TYPE_CHOICES = [
        (TEXT, 'Text'),
        (IMAGE, 'Image'),
        (VIDEO, 'Video'),
        (FILE, 'File'),
        (AUDIO, 'Audio'),
    ]
    
    # Type choices for the sender and receiver
    BUREAU = 'bureau'
    STARTUP = 'startup'
    PERSONNE = 'personne'
    
    ENTITY_TYPE_CHOICES = [
        (BUREAU, 'Bureau d\'Étude'),
        (STARTUP, 'Startup'),
        (PERSONNE, 'Personne'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    chat = models.ForeignKey(Chat, on_delete=models.CASCADE, related_name='messages')
    
    # Sender information
    sender_type = models.CharField(max_length=10, choices=ENTITY_TYPE_CHOICES)
    sender_id = models.IntegerField()  # ID of the sender (bureau_id or startup_id)
    
    # Receiver information
    receiver_type = models.CharField(max_length=10, choices=ENTITY_TYPE_CHOICES)
    receiver_id = models.IntegerField()  # ID of the receiver
    
    # Content type and actual content
    content_type = models.CharField(max_length=5, choices=CONTENT_TYPE_CHOICES, default=TEXT)
    text_content = models.TextField(blank=True, null=True)
    media_file = models.FileField(upload_to=message_file_path, blank=True, null=True)
    
    # Metadata
    timestamp = models.DateTimeField(default=timezone.now)
    is_read = models.BooleanField(default=False)
    read_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['timestamp']
    
    def __str__(self):
        return f"Message in {self.chat} at {self.timestamp}"

    def mark_as_read(self):
        if not self.is_read:
            self.is_read = True
            self.read_at = timezone.now()
            self.save(update_fields=['is_read', 'read_at'])


# Message Content models to associate with a message
class MessageAttachment(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    message = models.ForeignKey(Message, on_delete=models.CASCADE, related_name='attachments')
    file = models.FileField(upload_to=message_file_path)
    file_name = models.CharField(max_length=255)
    file_size = models.IntegerField()  # Size in bytes
    file_type = models.CharField(max_length=100)  # MIME type
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Attachment for {self.message}" 


class ConsultationType(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    
    def __str__(self):
        return self.name

class ConsultationRequest(models.Model):
    PENDING = 'pending'
    ACCEPTED = 'accepted'
    REJECTED = 'rejected'
    COMPLETED = 'completed'
    
    STATUS_CHOICES = [
        (PENDING, 'Pending'),
        (ACCEPTED, 'Accepted'),
        (REJECTED, 'Rejected'),
        (COMPLETED, 'Completed'),
    ]
    
    bureau = models.ForeignKey(BureauEtude, on_delete=models.CASCADE, related_name='consultation_requests')
    startup = models.ForeignKey(Startup, on_delete=models.CASCADE, related_name='consultation_requests')
    consultation_type = models.ForeignKey(ConsultationType, on_delete=models.SET_NULL, null=True)
    problem_description = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=PENDING)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Consultation request from {self.startup.nom} to {self.bureau.nom}"

class PaymentRequest(models.Model):
    consultation = models.OneToOneField(ConsultationRequest, on_delete=models.CASCADE, related_name='payment_request')
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    payment_method = models.CharField(max_length=100, default='Baird Mob')
    is_paid = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):git push -u origin main
        return f"Payment request for {self.consultation} - {self.amount} DA"
    