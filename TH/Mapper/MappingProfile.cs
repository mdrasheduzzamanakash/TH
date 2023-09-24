using AutoMapper;

namespace TH.Mapper
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            //CreateMap<UserCreationViewModel, UserSingleInDTO>()
            //    .ForMember(dest => dest.Image, opt => opt.MapFrom(src => ConvertToByteArray(src.Image)))
            //    .ForMember(dest => dest.FileFormat, opt => opt.MapFrom(src => src.Image.ContentType));
        }
    }
}
