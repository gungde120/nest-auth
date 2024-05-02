import { IsEmail, IsNotEmpty, IsString, Length } from 'class-validator';

export class AuthDto {
  @IsEmail()
  public email: string;

  @IsNotEmpty()
  @IsString()
  @Length(8, 20, {
    message: 'Password has to be at between 8 and 20 characters',
  })
  public password: string;
}
