using AutoMapper;
using Microsoft.EntityFrameworkCore;
using TH.Data;
using TH.Domains;

namespace TH.Services
{
    public class RefreshTokenService : GenericService<RefreshToken>, IRefreshTokenService, IGenericService<RefreshToken>
    {
        public RefreshTokenService(AppDbContext context, ILogger logger, IMapper mapper) : base(context, logger, mapper)
        {
        }

        public async Task<RefreshToken?> FindByIdentityIdAsync(string id)
        {
            if (id == null) throw new ArgumentNullException(nameof(id));
            var token = await _dbSet.FirstOrDefaultAsync(u => u.IdentityId == id);
            return token;
        }
    }
}
