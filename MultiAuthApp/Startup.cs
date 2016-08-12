using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(MultiAuthApp.Startup))]
namespace MultiAuthApp
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
