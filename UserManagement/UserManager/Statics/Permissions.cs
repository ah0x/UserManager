namespace UserManagement.UserManager.Statics
{
    public class Permissions
    {
        public static List<string> GeneratePermissions(string module) => new List<string>()
        {
            $"Permissions.{module}.Create",
            $"Permissions.{module}.View",
            $"Permissions.{module}.Edit",
            $"Permissions.{module}.Delete",
        };

        public static class Products
        {
            public const string View = "Permissions.Products.View";
            public const string Delete = "Permissions.Products.Delete";
            public const string Edit = "Permissions.Products.Edit";
            public const string Create = "Permissions.Products.Create";
        }

        public static class Dashboard
        {
            public const string View = "Permissions.Dashboard.View";
            public const string Delete = "Permissions.Dashboard.Delete";
            public const string Edit = "Permissions.Dashboard.Edit";
            public const string Create = "Permissions.Dashboard.Create";
        }

        public static class RolesPolicy
        {
            public const string View = "Permissions.RolesPolicy.View";
            public const string Delete = "Permissions.RolesPolicy.Delete";
            public const string Edit = "Permissions.RolesPolicy.Edit";
            public const string Create = "Permissions.RolesPolicy.Create";
        }

        public static class UserPolicy
        {
            public const string View = "Permissions.UserPolicy.View";
            public const string Delete = "Permissions.UserPolicy.Delete";
            public const string Edit = "Permissions.UserPolicy.Edit";
            public const string Create = "Permissions.UserPolicy.Create";
        }

        public static class Receipts
        {
            public const string View = "Permissions.Receipts.GetProductReceits";
            public const string Delete = "Permissions.Receipts.CreateReceipts";
        }
    }
}
