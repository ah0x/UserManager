using Microsoft.AspNetCore.Identity;
using System.Reflection;
using UserManagement.UserManager.AuthModels;

namespace UserManagement.Helper
{
    public static class ClaimsHelper
    {
        public static void GetPermission(this List<RoleClaimViewModel> allPermissions, Type policy, string roleId)
        {
            FieldInfo[] fields = policy.GetFields(BindingFlags.Static | BindingFlags.Public);

            foreach (var item in fields)
            {
                allPermissions.Add(new RoleClaimViewModel() { Value = item.GetValue(null).ToString(), Type = "Permissions" });
            }
        }

        public async static Task AddPermissionClaim(this RoleManager<IdentityRole> roleManager, IdentityRole role, string permission)
        {
            var allClaims = await roleManager.GetClaimsAsync(role);

            if (!allClaims.Any(a => a.Type == "Permission" && a.Value == permission))
            {
                await roleManager.AddClaimAsync(role, new System.Security.Claims.Claim("Permission", permission));
            }
        }

    }
}
