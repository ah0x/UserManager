using Microsoft.AspNetCore.Identity;
using UserManagement.UserManager.AuthModels;
using UserManagement.UserManager.Statics;

namespace UserManagement.UserManager.Seeds
{
    public class DefaultRoles
    {
        public static async Task SeedAsync(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            await roleManager.CreateAsync(new IdentityRole(Roles.SuperAdmin.ToString()));
            await roleManager.CreateAsync(new IdentityRole(Roles.Agent.ToString()));
            await roleManager.CreateAsync(new IdentityRole(Roles.Custmer.ToString()));
        }
    }
}
