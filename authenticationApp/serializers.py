# authentication/serializers.py
from rest_framework import serializers
from django.contrib.auth import get_user_model
import jwt
from django.conf import settings
from django.utils import timezone
from datetime import datetime, timedelta
from rest_framework.exceptions import ValidationError
from django.core.mail import send_mail
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

User = get_user_model()

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    role = serializers.ChoiceField(choices=User.ROLE_CHOICES, default='admin')  # Add the role field

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'role']

    def create(self, validated_data):
        user = User(
            username=validated_data['username'],
            email=validated_data['email'],
            role=validated_data.get('role', 'normal')  # set default role to 'normal' if not provided
        )
        user.set_password(validated_data['password'])
        user.save()
        return user

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    def validate(self, data):
        user = User.objects.filter(email=data['email']).first()
        if user and user.check_password(data['password']):
            # token = self.get_token(user)
            token = AccessToken.for_user(user)  # creates AccessToken  instance for the user
            return {
                'email': user.email,
                'token': token,  # use Simple JWT to create token
            }
        raise serializers.ValidationError('Invalid credentials')

    def get_token(self, user):
        payload = {
            'id': user.id,
            'email': user.email,
            'exp': timezone.now() + timedelta(hours=24),
            'iat': timezone.now(),
        }
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
        return token
    
class InviteUserSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise ValidationError('User with this email already exists')
        return value
    
    def create(self, validated_data):
        email = validated_data['email']
        password = User.objects.make_random_password()
        user = User.objects.create_user(
            username=email.split('@')[0],
            email=email,
            password=password,
            role='normal',
            must_change_password=True  # Ensure the user changes their password upon first login
        )

        # save the temporary password to send it in the email
        user.password = password

        return user
    
class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)        

    def validate_old_password(self, value):
        user = self.context['request'].user
        print(f"Provided password: {value}, Hashed password: {user.password}")
        if not user.check_password(value):
            print("Password validation failed")
            raise ValidationError('Old password is incorrect')
        return value
    
    def update(self, instance, validated_data):
        # set the new password using the provided 'new_password' field
        instance.set_password(validated_data['new_password'])
        instance.save()
        return instance
    