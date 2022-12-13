using Microsoft.AspNetCore.Identity;
using UserManagement.UserManager.AuthModels;
using UserManagement.UserManager.Statics;

namespace UserManagement.UserManager.Seeds
{
    public class DefaultRoles
    {
        public static async Task SeedAsync(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            if (await roleManager.FindByNameAsync(Roles.SuperAdmin.ToString()) == null)
            {
                await roleManager.CreateAsync(new IdentityRole(Roles.SuperAdmin.ToString()));
            }

            if (await roleManager.FindByNameAsync(Roles.Agent.ToString()) == null)
            {
                await roleManager.CreateAsync(new IdentityRole(Roles.Agent.ToString()));
            }

            if (await roleManager.FindByNameAsync(Roles.Custmer.ToString()) == null)
            {
                await roleManager.CreateAsync(new IdentityRole(Roles.Custmer.ToString()));
            }
        }
    }
}
