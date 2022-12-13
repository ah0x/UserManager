using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using UserManagement.Helper;
using UserManagement.Interfaces;
using UserManagement.UserManager.AuthModels;
using UserManagement.UserManager.Statics;

namespace UserManagement.Service
{
    public class UserManagerService:IUserManagerService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public UserManagerService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
        }

        public async Task<PermissionViewModel> GetPermissionsByRoleId(string roleId)
        {
            var model = new PermissionViewModel();
            var allPermissions = new List<RoleClaimViewModel>();

            allPermissions.GetPermission(typeof(Permissions.Products), roleId);
            allPermissions.GetPermission(typeof(Permissions.Dashboard), roleId);
            allPermissions.GetPermission(typeof(Permissions.RolesPolicy), roleId);
            allPermissions.GetPermission(typeof(Permissions.UserPolicy), roleId);

            var role = await _roleManager.FindByIdAsync(roleId);
            model.RoleId = roleId;
            var claims = await _roleManager.GetClaimsAsync(role);
            var allClaimValues = allPermissions.Select(a => a.Value).ToList();
            var roleClaimValues = claims.Select(a => a.Value).ToList();
            var authorizedClaims = allClaimValues.Intersect(roleClaimValues).ToList();
            foreach (var permission in allPermissions)
            {
                if (authorizedClaims.Any(a => a == permission.Value))
                {
                    permission.Selected = true;
                }
            }
            model.RoleClaims = allPermissions;
            return model;
        }

        public async Task<List<ApplicationUser>> GetAllUsers()
        {
            var users = await _userManager.Users.Select(c => new ApplicationUser()
            {
                
                FirstName = c.FirstName,
                LastName = c.LastName,
                Email = c.Email,
                CreatedDate = c.CreatedDate,
                EmailConfirmed = c.EmailConfirmed,
                Id = c.Id,
                PhoneNumber = c.PhoneNumber,
                UserName = c.UserName,
            }).ToListAsync();

            return users;
        }

        public async Task<ManageUserRoleViewModel> GetUserRoleByUserId(string userId)
        {
            var userRolesVM = new List<UserRolesViewModel>();
            var user = await _userManager.FindByIdAsync(userId);

            foreach (var role in _roleManager.Roles)
            {
                var userRoleVM = new UserRolesViewModel()
                {
                    RoleName = role.Name,
                };

                if (await _userManager.IsInRoleAsync(user, userRoleVM.RoleName))
                {
                    userRoleVM.Selected = true;
                }
                else
                {
                    userRoleVM.Selected = false;
                }

                userRolesVM.Add(userRoleVM);
            }

            var model = new ManageUserRoleViewModel()
            {
                UserId = userId,
                UserRoles = userRolesVM
            };

            return model;
        }

        public async Task<ApplicationUser> GetUserById(string userId)
        {
            if (userId == null)
            {
                return null;
            }
            return await _userManager.FindByIdAsync(userId);
        }

        public async Task<IdentityRole> GetRoleByRoleId(string roleId)
        {
            if (roleId == null)
            {
                return null;
            }
            var role = await _roleManager.Roles.Where(x => x.Id == roleId).FirstOrDefaultAsync();
            if (role == null)
            {
                return null;
            }
            if (role.Name == "SuperAdmin" || role.Name == "Agent" || role.Name == "Custmer")
            {
                return null;
            }
            return role;
        }

        public async Task<bool> IsRoleInUse(string roleName)
        {
            if (roleName == null)
            {
                return false;
            }

            var users = await _userManager.Users.ToListAsync();
            foreach(var user in users)
            {
                if (_userManager.IsInRoleAsync(user, roleName).Result == true)
                {
                    return true;
                }
            }
            return false;
        }

        public async Task<string> SaveUserImage(IFormFile file)
        {
            if (file != null)
            {
                string imgext = Path.GetExtension(file.FileName);
                if (imgext == ".jpg" || imgext == ".png" || imgext == ".jpeg")
                {
                    if (file.Length > 0)
                    {
                        var filePath = Path.Combine(Directory.GetCurrentDirectory(), @"wwwroot\Images\", file.FileName);

                        using (var stream = System.IO.File.Create(filePath))
                        {
                            await file.CopyToAsync(stream);
                        }
                        return Path.Combine("/Images/" + file.FileName);
                    }
                }
            }
            return "/Images/DeffultUser";
        }
    }
}
