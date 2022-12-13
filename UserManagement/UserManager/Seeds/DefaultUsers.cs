using Microsoft.AspNetCore.Identity;
using UserManagement.UserManager.AuthModels;
using UserManagement.UserManager.Statics;
using UserManagement.Helper;

namespace UserManagement.UserManager.Seeds
{
    public static class DefaultUsers
    {
        private const string Default_Password = "QW!@qw12";

        private static ApplicationUser SuperAdminUser = new ApplicationUser()
        {
            FirstName = "Admin",
            LastName = "Admin",
            UserName = "Admin@Tm.Iq",
            Email = "Admin@Tm.Iq",
            EmailConfirmed = true,
            PhoneNumberConfirmed = true
        };

        public static async Task SeedSuperAdminUsersAsync(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            var user = await userManager.FindByEmailAsync(SuperAdminUser.Email);

            if (user == null)
            {
                await userManager.CreateAsync(SuperAdminUser, Default_Password);

                await userManager.AddToRoleAsync(SuperAdminUser, Roles.SuperAdmin.ToString());
            }

            await roleManager.SeedClaimsForSuperAdmin();
        }

        private async static Task SeedClaimsForSuperAdmin(this RoleManager<IdentityRole> roleManager)
        {
            var superAdminRole = await roleManager.FindByNameAsync(Roles.SuperAdmin.ToString());
            await roleManager.AddPermissionClaim(superAdminRole, "Products");
            await roleManager.AddPermissionClaim(superAdminRole, "Dashboard");
            await roleManager.AddPermissionClaim(superAdminRole, "RolesPolicy");
            await roleManager.AddPermissionClaim(superAdminRole, "UserPolicy");
        }

        private async static Task AddPermissionClaim(this RoleManager<IdentityRole> roleManager, IdentityRole role, string module)
        {
            var allClaims = await roleManager.GetClaimsAsync(role);
            var allPermissions = Permissions.GeneratePermissions(module);

            foreach (var permission in allPermissions)
            {
                if (!allClaims.Any(a => a.Type == "Permission" && a.Value == permission))
                {
                    await roleManager.AddClaimAsync(role, new System.Security.Claims.Claim("Permission", permission));
                }

            }

        }
    }
}
