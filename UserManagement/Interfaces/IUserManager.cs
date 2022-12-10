using UserManagement.UserManager.AuthModels;

namespace UserManagement.Interfaces
{
    public interface IUserManagerService
    {
        public Task<List<ApplicationUser>> GetAllUsers();
    }
}
