using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using UserManagement.Interfaces;
using UserManagement.UserManager.AuthModels;

namespace UserManagement.Service
{
    public class UserManagerService:IUserManagerService
    {
        private readonly UserManager<ApplicationUser> _userManager;

        public UserManagerService(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        public async Task<List<ApplicationUser>> GetAllUsers()
        {
            var users = await _userManager.Users.Select(x =>new { x.FullName, x.PhoneNumber, x.UserName, x.Email}).ToListAsync();



            return await _userManager.Users.ToListAsync();
        }
    }
}
