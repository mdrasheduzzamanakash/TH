using System.Security.Claims;
using TH.Domains;

namespace TH.Services
{
    public class WorkContext : IWorkContext
    {
        private Customer CurrentCustomer { get; set; }
        
        private List<string> Roles { get; set; }

        public WorkContext()
        {
            CurrentCustomer = new Customer();
            Roles = new List<string>();
        }

        public Customer GetCurrentCustomer()
        {
            return CurrentCustomer;
        }

        public List<string> GetCurrentCustomerRoles()
        {
            return Roles;
        }

        public void SetCurrentCustomer(Customer customer)
        {
            CurrentCustomer = customer;
        }

        public void SetCurrentCustomerRoles(List<string> roles)
        {
            Roles = roles ;
        }
    }
}
