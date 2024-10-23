from django.db import models
from django.apps import apps
from django.contrib.auth.models import (PermissionsMixin, AbstractBaseUser, UserManager)
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.contrib.auth.hashers import make_password
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
import jwt
from django.conf import settings   #we will be using secret keys 
from datetime import datetime, timedelta

# Create your models here
class MyUserManager(UserManager):
    def _create_user(self, username, email, password, **extra_fields):
        """
        Create and save a user with the given username, email, and password.
        """
        if not username:    
            raise ValueError("The given username must be set")
        if not email:
            raise ValueError("The given email must be set")
        email = self.normalize_email(email)

        GlobalUserModel = apps.get_model(
            self.model._meta.app_label, self.model._meta.object_name
        )
        username = GlobalUserModel.normalize_username(username)
        user = self.model(username=username, email=email, **extra_fields)
        user.password = make_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, username, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        extra_fields.setdefault("role", "normal")
        return self._create_user(username, email, password, **extra_fields)

    def create_superuser(self, username, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("role", "admin")

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self._create_user(username, email, password, **extra_fields)

class User(AbstractBaseUser, PermissionsMixin):
    
    """
    An abstract base class implementing a fully featured User model with
    admin-compliant permissions.

    Username and password are required. Other fields are optional.
    """

    username_validator = UnicodeUsernameValidator()

    username = models.CharField(
        _("username"),
        max_length=150,
        unique=True,
        help_text=_(
            "Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only."
        ),
        validators=[username_validator],
        error_messages={
            "unique": _("A user with that username already exists."),
        },
    )

    ROLE_CHOICES = (
        ('admin', 'Admin'),
        ('normal', 'Normal'),
    )
    role = models.CharField(
        max_length=10,
        choices=ROLE_CHOICES,
        default='normal',
        blank=False,     #will be true only after user has clicked the link sent to them
        help_text=("Designates the role of the user. The default is normal. "),
    )

    # first_name = models.CharField(_("first name"), max_length=150, blank=True)
    # last_name = models.CharField(_("last name"), max_length=150, blank=True)
    email = models.EmailField(_("email address"), blank=False, unique=True)
    is_staff = models.BooleanField(
        _("staff status"),
        default=False,
        help_text=_("Designates whether the user can log into this admin site."),
    )
    is_active = models.BooleanField(
        _("active"),
        default=True,
        help_text=_(
            "Designates whether this user should be treated as active. "
            "Unselect this instead of deleting accounts."
        ),
    )
    date_joined = models.DateTimeField(_("date joined"), default=timezone.now)

    email_verified=models.BooleanField(
        _("email_verified"),
        default=False,     #will be true only after user has clicked the link sent to them
        help_text=_(
            "Designates whether this user's email is verified. "
        )            
    )
    
    must_change_password = models.BooleanField(
        default=True,
        help_text="Designates whether this user must change their password at the next login."
    )
    objects = MyUserManager()

    EMAIL_FIELD = "email"
    USERNAME_FIELD = "email"  
    REQUIRED_FIELDS = ["username"]

    @property
    def token(self):

        token = jwt.encode({'username': self.username, 'email': self.email, 'exp': datetime.now(datetime.timezone.utc) + timedelta(hours=24)},
                settings.SECRET_KEY, # secret key for encoding the JWT. application secret key is used here
                algorithm='HS256'   #specify the algorithm to use
        )
        return token
