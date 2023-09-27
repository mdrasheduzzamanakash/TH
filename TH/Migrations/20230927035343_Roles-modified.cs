using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace TH.Migrations
{
    /// <inheritdoc />
    public partial class Rolesmodified : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "5530120e-3c49-45f8-80c1-c1e65d7072a2");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "582e6b8c-59fa-41a5-92b9-9f526f3d8f05");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "74019e6e-dd6a-45a0-a58a-3c183f200ac5");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "b9d2ce12-c047-4ed5-b800-23f6c7e60b33");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "dbd34ae6-df5c-45d0-ac2d-2e2b4bc75a63");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "e8c274e8-5a3b-4f19-a009-6fa0f0d381d8");

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "4c102a4b-6b2a-4b32-b697-1a5479ce1c29", "6", "Guest", "Guest" },
                    { "5828c9aa-d2cd-4734-b087-39114bcd89e6", "2", "Doctor", "Doctor" },
                    { "6aa6fca6-8898-43c7-945a-019039353b50", "1", "Admin", "Admin" },
                    { "6c051ad1-5394-4e0d-92bc-63a030a233b3", "5", "PatientUnverified", "PatientUnvarified" },
                    { "bdf75c28-a8ac-498d-a2d4-d1044b7fad4a", "4", "Patient", "Patient" },
                    { "e5b2ac6e-332b-4f5c-ab30-8a658deb95bc", "3", "DoctorUnverified", "DoctorUnvarified" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "4c102a4b-6b2a-4b32-b697-1a5479ce1c29");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "5828c9aa-d2cd-4734-b087-39114bcd89e6");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "6aa6fca6-8898-43c7-945a-019039353b50");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "6c051ad1-5394-4e0d-92bc-63a030a233b3");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "bdf75c28-a8ac-498d-a2d4-d1044b7fad4a");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "e5b2ac6e-332b-4f5c-ab30-8a658deb95bc");

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "5530120e-3c49-45f8-80c1-c1e65d7072a2", "3", "Doctor", "Doctor" },
                    { "582e6b8c-59fa-41a5-92b9-9f526f3d8f05", "2", "Registered", "Registered" },
                    { "74019e6e-dd6a-45a0-a58a-3c183f200ac5", "4", "DoctorUnvarified", "DoctorUnvarified" },
                    { "b9d2ce12-c047-4ed5-b800-23f6c7e60b33", "5", "Patient", "Patient" },
                    { "dbd34ae6-df5c-45d0-ac2d-2e2b4bc75a63", "1", "Admin", "Admin" },
                    { "e8c274e8-5a3b-4f19-a009-6fa0f0d381d8", "6", "Guest", "Guest" }
                });
        }
    }
}
