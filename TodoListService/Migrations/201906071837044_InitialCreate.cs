namespace TodoListService.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class InitialCreate : DbMigration
    {
        public override void Up()
        {
            CreateTable(
                "dbo.PerWebUserCaches",
                c => new
                    {
                        EntryId = c.Int(nullable: false, identity: true),
                        WebUserUniqueId = c.String(),
                        CacheBits = c.Binary(),
                        LastWrite = c.DateTime(nullable: false),
                        RowVersion = c.Binary(nullable: false, fixedLength: true, timestamp: true, storeType: "rowversion"),
                    })
                .PrimaryKey(t => t.EntryId);
            
            CreateTable(
                "dbo.TodoItems",
                c => new
                    {
                        ID = c.Int(nullable: false, identity: true),
                        Title = c.String(),
                        Owner = c.String(),
                    })
                .PrimaryKey(t => t.ID);
            
        }
        
        public override void Down()
        {
            DropTable("dbo.TodoItems");
            DropTable("dbo.PerWebUserCaches");
        }
    }
}
