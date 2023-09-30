using AutoMapper;
using Microsoft.EntityFrameworkCore;
using TH.Data;
using TH.Domains;

namespace TH.Services
{
    public class CustomerService : GenericService<Customer>, ICustomerService, IGenericService<Customer>
    {
        public CustomerService(AppDbContext context, IMapper mapper) : base(context, mapper)
        {
        }

        public async Task<Customer?> FindByEmailAsync(string email)
        {
            if (email == null) throw new ArgumentNullException(nameof(email));
            var user = await _dbSet.FirstOrDefaultAsync(u => u.Email == email);
            return user;
        }
    }
}
