using Microsoft.EntityFrameworkCore.Migrations;

namespace AuthServer.Infrastructure.Migrations
{
    public partial class addseeddataforrole : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[] { "233f21c5-cbd5-4c3d-b467-c7d6da80267d", "f5a8cfd9-e1dd-4ce0-86ff-fa7bbe868d0f", "consumer", "CONSUMER" });
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "233f21c5-cbd5-4c3d-b467-c7d6da80267d");
        }
    }
}
