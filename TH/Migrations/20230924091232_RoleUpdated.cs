using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace TH.Migrations
{
    /// <inheritdoc />
    public partial class RoleUpdated : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
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

            migrationBuilder.CreateTable(
                name: "Customers",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    FirstName = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    LastName = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    IdentityId = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    OnRole = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Customers", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "RefreshTokens",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Token = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Status = table.Column<bool>(type: "bit", nullable: false),
                    JwtId = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    IsUsed = table.Column<bool>(type: "bit", nullable: false),
                    IsRevoked = table.Column<bool>(type: "bit", nullable: false),
                    ExpiryDate = table.Column<DateTime>(type: "datetime2", nullable: false),
                    UserId = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    IdentityId = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RefreshTokens", x => x.Id);
                });

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

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Customers");

            migrationBuilder.DropTable(
                name: "RefreshTokens");

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
                    { "89bd1cad-033e-4c81-b4ab-9f2768992d7a", "3", "Doctor", "Doctor" },
                    { "95e99de8-ce06-4d0e-a9f9-0f3c857168d9", "1", "Admin", "Admin" },
                    { "a3325ba3-9559-4af5-8c80-2408819e733f", "5", "Guest", "Guest" },
                    { "bf686531-c8ce-42d5-ad89-e3fabe8ef4b3", "2", "Registered", "Registered" },
                    { "ccd92db1-6f64-407a-9b3f-a17259257759", "4", "Patient", "Patient" }
                });
        }
    }
}
