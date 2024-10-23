from django.shortcuts import render
from rest_framework import generics, status
from .serializers import RegisterSerializer, LoginSerializer, InviteUserSerializer, ChangePasswordSerializer
from django.contrib.auth import get_user_model
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from django.conf import settings
from django.core.mail import send_mail

# Create your views here.
User = get_user_model()

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]

class LoginView(APIView):
    permission_classes = [AllowAny]
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        token = str(serializer.validated_data['token'])

        user = User.objects.get(email=serializer.validated_data['email'])

        # Check if the user is a normal user and needs to change their password
        if user.role == 'normal' and user.must_change_password:
            return Response({
                'message': 'You must change your password before continuing.',
                'must_change_password': True,
                'token': token,  # include the token in the response
            }, status=status.HTTP_200_OK)

        # return Response({serializer.validated_data}, status=status.HTTP_200_OK)
        return Response({'token': token, 'email': f'{user.email}', 'role': f'{user.role}'}, status=status.HTTP_200_OK)
    
class InviteUserView(generics.CreateAPIView):
    serializer_class = InviteUserSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return User.objects.filter(role='admin')
    
    def post(self, request, *args, **kwargs):
        # only admins can invite users
        if request.user.role != 'admin':
            return Response({'Error': 'Only admins can invite users'}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        # generate a token for the invited user
        token = str(AccessToken.for_user(user))  

        # Generate login link and send email to user
        login_link = f"{settings.FRONTEND_URL}/login"

        # send the email with the login link and a one-time password
        send_mail(
            subject="Invitation to join Eclectics Analytics",
            message=f"Hello, you have been invited to join the Eclectics Analytics platform. "
                    f"Your temporary password is: {user.password}. "
                    f"Please log in using the following link: {login_link}. "
                    f"You will be prompted to change your password upon first login.",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
        )

        return Response({
            'message': f'User with email {user.email} invited successfully. An email has been sent to the user with login details.', 
            'token': token
            }, status=status.HTTP_201_CREATED)
    
class ChangePasswordView(generics.UpdateAPIView):
    serializer_class = ChangePasswordSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user