using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using UserManagement.UserManager.AuthModels;

namespace UserManagement.Interfaces
{
    public interface IUserManagerService
    {
        public Task<List<ApplicationUser>> GetAllUsers();

        public Task<ApplicationUser> GetUserById(string userId);

        public Task<ManageUserRoleViewModel> GetUserRoleByUserId(string userId);

        public Task<PermissionViewModel> GetPermissionsByRoleId(string roleId);

        public Task<IdentityRole> GetRoleByRoleId(string roleId);

        public Task<bool> IsRoleInUse(string roleName);

        public Task<string> SaveUserImage(IFormFile file);
    }
}
