namespace UserManagement.UserManager.AuthModels
{
    public class PermissionViewModel
    {
        public string RoleId { get; set; }
        public IList<RoleClaimViewModel> RoleClaims { get; set; }
    }

    public class RoleClaimViewModel
    {
        public string Type { get; set; }
        public string Value { get; set; }
        public bool Selected { get; set; }
    }
}
