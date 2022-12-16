import {inject} from '@loopback/core';
import {compare, genSalt, hash} from 'bcryptjs';
// import {PasswordHasherBindings} from '../keys';

export interface PasswordHasher<T = string> {
  hashPassword(Password: T): Promise<T>;
  comparePassword(providedPass: T, storedPass: T): Promise<Boolean>;
}

export class BcryptHasher implements PasswordHasher<string> {
  async comparePassword(
    providedPass: string,
    storedPass: string,
  ): Promise<Boolean> {
    const passwordMatched = await compare(providedPass, storedPass);

    return passwordMatched;
  }
  @inject('rounds')
  public readonly rounds: number;

  async hashPassword(Password: string) {
    const salt = await genSalt(this.rounds);
    return await hash(Password, salt);
  }
}
