using TH.Domains;

namespace TH.Services
{
    public interface IRefreshTokenService : IGenericService<RefreshToken>
    {
        Task<RefreshToken?> FindByIdentityIdAsync(string id);
    }
}
