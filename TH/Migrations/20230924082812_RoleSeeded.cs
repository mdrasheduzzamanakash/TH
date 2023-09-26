using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace TH.Migrations
{
    /// <inheritdoc />
    public partial class RoleSeeded : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "89bd1cad-033e-4c81-b4ab-9f2768992d7a", "3", "Doctor", "Doctor" },
                    { "95e99de8-ce06-4d0e-a9f9-0f3c857168d9", "1", "Admin", "Admin" },
                    { "a3325ba3-9559-4af5-8c80-2408819e733f", "5", "Guest", "Guest" },
                    { "bf686531-c8ce-42d5-ad89-e3fabe8ef4b3", "2", "Registered", "Registered" },
                    { "ccd92db1-6f64-407a-9b3f-a17259257759", "4", "Patient", "Patient" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "89bd1cad-033e-4c81-b4ab-9f2768992d7a");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "95e99de8-ce06-4d0e-a9f9-0f3c857168d9");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "a3325ba3-9559-4af5-8c80-2408819e733f");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "bf686531-c8ce-42d5-ad89-e3fabe8ef4b3");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "ccd92db1-6f64-407a-9b3f-a17259257759");
        }
    }
}
