using Microsoft.Owin;
using Owin;

[assembly: OwinStartup(typeof(TodoListService.Startup))]

namespace TodoListService
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
