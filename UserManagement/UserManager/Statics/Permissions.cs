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
            public const string View = "Permissions.Product.View";
            public const string Delete = "Permissions.Product.Delete";
            public const string Edit = "Permissions.Product.Edit";
            public const string Create = "Permissions.Product.Create";
        }

        public static class Dashboard
        {
            public const string View = "Permissions.Dashboard.View";
            public const string Delete = "Permissions.Dashboard.Delete";
            public const string Edit = "Permissions.Dashboard.Edit";
            public const string Create = "Permissions.Dashboard.Create";
        }

        public static class Receipts
        {
            public const string View = "Permissions.Receipts.GetProductReceits";
            public const string Delete = "Permissions.Receipts.CreateReceipts";
        }
    }
}
