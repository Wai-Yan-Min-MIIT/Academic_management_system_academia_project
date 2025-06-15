from .models import MIITUsers, Student, FacultyStaff, MIITRole


# from django.urls import resolve

def current_path(request):
    return {
        'current_path': request.path,
    }


def user_info(request):
    if request.user.is_authenticated:
        try:
            context_user_id = request.user.UserID
            context_miit_user = MIITUsers.objects.get(UserID=context_user_id)

            context_miit_username = context_miit_user.username.split('@')[0]
            context_selected_role_id = request.session.get('selected_role')
            context_selected_role_name = MIITRole.objects.filter(RoleID=context_selected_role_id).values_list('RoleDescription', flat=True).first()
            
            context_user = Student.objects.filter(UserID=context_user_id).values_list('StudentName', 'Salutation').first()
            if not context_user:
                context_user = FacultyStaff.objects.filter(UserID=context_user_id).values_list('FacultyStaffName', 'Salutation').first()

            if context_user:
                context_username, context_user_salutation = context_user
            else:
                context_username, context_user_salutation = None, None

            return {
                'UserSalutation': context_user_salutation,
                'UserName': context_username,
                'email_username': context_miit_username,
                'RoleName': context_selected_role_name,
            }
        except MIITUsers.DoesNotExist:
            return {}
    return {}
