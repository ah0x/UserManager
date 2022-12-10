namespace UserManagement.UserManager.AuthModels
{
    public class UserRolesViewModel
    {
        public string RoleName { get; set; }
        public bool Selected { get; set; }
    }

    public class ManageUserRoleViewModel
    {
        public string UserId { get; set; }
        public IList<UserRolesViewModel> UserRoles { get; set; }
    }
}
