import {inject} from '@loopback/core';
import {HttpErrors} from '@loopback/rest';
import jwt from 'jsonwebtoken';
import {User} from '../models';
import {TokenServiceBindings} from './keys';

export const encodeJWT = (
  payload: string | object | Buffer,
  jwtSecret: string,
  expiresIn: string,
): Promise<unknown> => {
  return new Promise((resolve, reject) => {
    jwt.sign(
      {payload: payload},
      jwtSecret,
      {expiresIn: expiresIn},
      (err: any, token: unknown) => {
        if (err) return reject(err);
        else return resolve(token);
      },
    );
  });
};

export const verifyAsync = async (
  token: string,
  jwtSecret: string,
): Promise<any> => {
  try {
    const authInfo = await jwt.verify(token, jwtSecret);
    return authInfo;
  } catch (error) {
    console.error(error);
  }
};

export class JWTService {
  @inject(TokenServiceBindings.TOKEN_SECRET)
  public readonly jwtSecret: string;
  @inject(TokenServiceBindings.TOKEN_EXPIRES_IN)
  public readonly expiresIn: string;

  async generateToken(user: User): Promise<String> {
    if (!user) {
      throw new HttpErrors.Unauthorized(
        'Error while Generating token : appUserData is null',
      );
    }
    let token: any = '';
    try {
      token = await encodeJWT(user, this.jwtSecret, this.expiresIn);
    } catch (error) {
      throw new HttpErrors.Unauthorized(`error generating token ${error}`);
    }

    return token;
  }

  async verifyToken(token: string): Promise<User | any> {
    if (!token) {
      throw new HttpErrors.Unauthorized(
        `Error verifying token : 'token' is null`,
      );
    }

    let UserProfile: User;

    try {
      const {id, name} = await verifyAsync(token, this.jwtSecret);

      UserProfile = Object.assign({id, name});

      return UserProfile;
    } catch (error) {
      throw new HttpErrors.Unauthorized(
        `Error verifying token : ${error.message}`,
      );
    }
  }
}
