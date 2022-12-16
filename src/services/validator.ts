// import {HttpErrors} from '@loopback/rest';
import {HttpErrors} from '@loopback/rest';
import isEmail from 'isemail';
import {Credentials} from '../repositories/user.repository';

export const validateCredentials = ({email, password}: Credentials) => {
  // console.log(Email)
  // console.log(Password)
  if (!isEmail.validate(email)) {
    throw new HttpErrors.UnprocessableEntity('invalid Email');
    //  HttpErrors.UnprocessableEntity('invalid Email')
  }

  if (password.length < 8) {
    throw new HttpErrors.UnprocessableEntity(
      'password length should be greater than 8',
    );
  }
};
