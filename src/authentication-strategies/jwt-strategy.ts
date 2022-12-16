import {AuthenticationStrategy} from '@loopback/authentication';
import {inject} from '@loopback/core';
import {HttpErrors, RedirectRoute, Request} from '@loopback/rest';
import {UserProfile} from '@loopback/security';
import {ParamsDictionary} from 'express-serve-static-core';
import {ParsedQs} from 'qs';
import {JWTService} from '../services/jwt-service';
import {TokenServiceBindings} from '../services/keys';

export class JWTStrategy implements AuthenticationStrategy {
  constructor(
    @inject(TokenServiceBindings.TOKEN_SERVICE)
    public jwtService: JWTService,
  ) {}
  name: string = 'jwt';
  async authenticate(
    request: Request<ParamsDictionary, any, any, ParsedQs, Record<string, any>>,
  ): Promise<UserProfile | RedirectRoute | undefined> {
    const token: string = this.extractCredentials(request);
    const UserProfile = await this.jwtService.verifyToken(token);
    return Promise.resolve(UserProfile);
  }

  extractCredentials(request: Request): string {
    if (!request.headers.authorization) {
      throw new HttpErrors.Unauthorized('Authorization header is missing.');
    }
    const authHeaderValue = request.headers.authorization;
    //Authorization : Bearer  xxxc..yyy..zzz

    if (!authHeaderValue.startsWith('Bearer')) {
      throw new HttpErrors.Unauthorized(
        'Authorization header is not type of Bearer ',
      );
    }

    const parts = authHeaderValue.split(' ');

    if (parts.length !== 2) {
      throw new HttpErrors.Unauthorized(`
      Authorization header has too many parts it
      must follow this pattern Bearer  xxxc..yyy..zzz
       `);
    }

    const token = parts[1];
    return token;
  }
}
