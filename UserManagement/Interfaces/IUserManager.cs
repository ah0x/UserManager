using UserManagement.UserManager.AuthModels;

namespace UserManagement.Interfaces
{
    public interface IUserManagerService
    {
        public Task<List<ApplicationUser>> GetAllUsers();

        public Task<ApplicationUser> GetUserById(string userId);

        public Task<ManageUserRoleViewModel> GetUserRoleByUserId(string userId);

        public Task<PermissionViewModel> GetPermissionsByRoleId(string roleId);
    }
}
