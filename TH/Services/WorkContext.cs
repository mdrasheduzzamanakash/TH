using TH.Domains;

namespace TH.Services
{
    public class WorkContext : IWorkContext
    {
        private Customer _customer { get; set; }
        private List<string> _customerRoles { get; set; }

        public WorkContext() { }

        public Customer GetCurrentCustomer()
        {
            return _customer;
        }

        public List<string> GetCurrentCustomerRoles()
        {
            return _customerRoles;
        }

        public void SetCurrentCustomer(Customer customer)
        {
            _customer = customer;
        }

        public void SetCurrentCustomerRoles(List<string> roles)
        {
            _customerRoles = roles;
        }
    }
}
