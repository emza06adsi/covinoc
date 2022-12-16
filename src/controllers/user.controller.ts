import {authenticate} from '@loopback/authentication';
import {inject} from '@loopback/core';
import {Filter, FilterExcludingWhere, repository} from '@loopback/repository';
import {
  del,
  get,
  getJsonSchemaRef,
  getModelSchemaRef,
  param,
  post,
  put,
  requestBody,
  response,
} from '@loopback/rest';
import * as _ from 'lodash';
import {User} from '../models';
import {Credentials, UserRepository} from '../repositories';
import {BcryptHasher} from '../services/hash.password.bcrypt';
import {JWTService} from '../services/jwt-service';
import {
  PasswordHasherBindings,
  TokenServiceBindings,
  UserServiceBindings,
} from '../services/keys';
import {MyUserService} from '../services/user-service';
import {validateCredentials} from '../services/validator';

export class UserController {
  constructor(
    @repository(UserRepository)
    public userRepository: UserRepository,
    @inject(PasswordHasherBindings.PASSWORD_HASHER)
    public bcrypHasher: BcryptHasher,
    @inject(UserServiceBindings.USER_SERVICE)
    public userService: MyUserService,
    @inject(TokenServiceBindings.TOKEN_SERVICE)
    public jwtService: JWTService,
  ) {}

  @post('/signup', {
    responses: {
      '200': {
        description: 'AppUser',
        content: {
          schema: getJsonSchemaRef(User),
        },
      },
    },
  })
  async signup(@requestBody() userData: User) {
    const {email, password} = userData;
    validateCredentials(_.pick({email, password}, ['email', 'password']));

    userData.password = await this.bcrypHasher.hashPassword(password);

    // validateCredentials(_.pick({email, password}, ['email', 'password']));
    let savedUser = await this.userRepository.create(userData);
    // delete savedUser.password
    return savedUser;
    // const {Email, Password = ''} = appUserData;
    // validateCredentials(_.pick({Email, Password}, ['Email', 'Password']));
    // appUserData.permissions = [PermissionKeys.AccessAuthFeature];
    // appUserData.Password = await this.hasher.hashPassword(Password);
    // const savedAppUserTb = await this.appUserTbRepository.create(appUserData)
    // delete savedAppUserTb.Password;
    // return savedAppUserTb;
  }

  @post('user/login', {
    responses: {
      '200': {
        description: 'Token',
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                token: {
                  type: 'string',
                },
              },
            },
          },
        },
      },
    },
  })
  async login(
    @requestBody() credentials: Credentials,
  ): Promise<{token: String}> {
    const user = await this.userService.verifyCredentials(credentials);
    console.log(user);
    const UserProfile = await this.userService.convertToUserProfile(user);
    console.log(UserProfile);
    // generate a jwt web token
    const token = await this.jwtService.generateToken(UserProfile);
    return Promise.resolve({token});
  }

  @get('/users')
  @response(200, {
    description: 'Array of User model instances',
    content: {
      'application/json': {
        schema: {
          type: 'array',
          items: getModelSchemaRef(User, {includeRelations: true}),
        },
      },
    },
  })
  async find(@param.filter(User) filter?: Filter<User>): Promise<User[]> {
    return this.userRepository.find(filter);
  }

  @get('/users/{id}')
  @authenticate('jwt')
  @response(200, {
    description: 'User model instance',
    content: {
      'application/json': {
        schema: getModelSchemaRef(User, {includeRelations: true}),
      },
    },
  })
  async findById(
    @param.path.number('id') id: number,
    @param.filter(User, {exclude: 'where'}) filter?: FilterExcludingWhere<User>,
  ): Promise<User> {
    return this.userRepository.findById(id, filter);
  }

  @put('/users/{id}')
  @authenticate('jwt')
  @response(204, {
    description: 'User PUT success',
  })
  async replaceById(
    @param.path.number('id') id: number,
    @requestBody() user: User,
  ): Promise<void> {
    await this.userRepository.replaceById(id, user);
  }

  @del('/users/{id}')
  @authenticate('jwt')
  @response(204, {
    description: 'User DELETE success',
  })
  async deleteById(@param.path.number('id') id: number): Promise<void> {
    await this.userRepository.deleteById(id);
  }
}
