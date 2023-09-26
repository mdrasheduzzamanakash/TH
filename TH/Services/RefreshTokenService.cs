using AutoMapper;
using TH.Data;
using TH.Domains;

namespace TH.Services
{
    public class RefreshTokenService : GenericService<RefreshToken>, IRefreshTokenService, IGenericService<RefreshToken>
    {
        public RefreshTokenService(AppDbContext context, ILogger logger, IMapper mapper) : base(context, logger, mapper)
        {
        }
    }
}
