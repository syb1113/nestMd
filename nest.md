# Nest

## 权限

### 用户token

把user的信息放在jwt中，通过jwt返回用户的token

>npm install --save @nestjs/jwt

把jwt服务在AppModule 里引入 JwtModule

```ts
JwtModule.register({
      global: true,
      secret: 'shiyb',
      signOptions: { expiresIn: '7d' },
    })
```

在用户需要的登录是触发jwtService，返回通过jwt的token

```ts
@Inject(JwtService)
private jwtService: JwtService;
```

```ts
@Post('login')
async login(@Body() loginUser: UserLoginDto){
  const user = await this.userService.login(loginUser);

  const token = this.jwtService.sign({
    user: {
      username: user.username,
      roles: user.roles
    }
  });

  return {
      token
  }
}
```

### 接口权限问题

通过login_guard来控制接口权限

>nest g guard login --no-spec --flat

在login.guard.ts中添加相关代码，来检查用户的登录状态

```ts

  //引入jwtService
  @Inject(JwtService)
  private jwtService: JwtService;
  
  //在canActivate方法中添加相关代码
  const request: Request = context.switchToHttp().getRequest();
    
  const authorization = request.headers.authorization;

  if(!authorization) {
    throw new UnauthorizedException('用户未登录');
  }

  try{
    const token = authorization.split(' ')[1];
    const data:Request = this.jwtService.verify(token);
    request.user = data.user;
    return true;
  } catch(e) {
    throw new UnauthorizedException('token 失效，请重新登录');
  }
```

扩展express的Request接口类型

```ts
declare module 'express'{
  interface Request{
    user:{
      //用户数据类型
    }
  }
}
```

全局添加登录守卫 LoginGuard 在app.module.ts中添加

```ts

{
  provide:APP_GUARD,
  useClass:LoginGuard
}

```

>**全局添加了登录守卫，所有路由都需要登录，那么登录接口也是需要权限的，为了避免这一点，需要用到SetMetadatal来进行控制,添加一个custom-decorator.ts来放自定义的装饰器**

```ts
import { SetMetadata } from "@nestjs/common";

export const  RequireLogin = () => SetMetadata('require-login', true);
```

>**在需要登录才能请求的接口上添加RequireLogin装饰器 用来区分哪些接口需要登录，哪些接口不需要。在 controller 上添加声明即可**

此时需要改造LoginGuard，去除目标的header的metadata来判断是否需要登录

### 登录的用户权限控制

此时需要做登录用户的权限控制，需要写个 PermissionGuard  同样声明成全局 Guard,并将UserServiceb暴露出去

>nest g guard permission --no-spec --flat

```ts
{
  useClass: PermissionGuard,
  provide: APP_GUARD,
},
```

需要在PermissionGuard中注入UserService,然后需要在userService里实现查询role的信息的service

```ts
//example
async findRolesByIds(roleIds: number[]) {
    return this.entityManager.find(Role, {
      where: {
        id: In(roleIds)
      },
      relations: {
        permissions: true
      }
    });
}
```

然后需要在PermissionGuard里调用下

```ts
import { CanActivate, ExecutionContext, Inject, Injectable } from '@nestjs/common';
import { Request } from 'express';
import { UserService } from './user/user.service';

@Injectable()
export class PermissionGuard implements CanActivate {

  @Inject(UserService) 
  private userService: UserService;

  async canActivate(
    context: ExecutionContext,
  ): Promise<boolean> {
    const request: Request = context.switchToHttp().getRequest();

    if(!request.user) {
      return true;
    }

    //此处调用userService获取用户权限
    const roles = await this.userService.findRolesByIds(request.user.roles.map(item => item.id))

    const permissions: Permission[]  = roles.reduce((total, current) => {
      total.push(...current.permissions);
      return total;
    }, []);

    console.log(permissions);

    return true;
  }
}
```

增加一个自定义的decorator装饰器，来确认哪些是需要权限的,然后在Controller 上声明需要的权限。

```ts
export const  RequirePermission = (...permissions: string[]) => SetMetadata('require-permission', permissions);
```

声明之后在权限守卫PermissionGuard中获取请求的权限名称，并判断是否包含在权限列表中

```ts
export class PermissionGuard implements CanActivate {
  @Inject(UserService)
  private userService: UserService;

  @Inject(Reflector)
  private reflector: Reflector;
  async canActivate(context: ExecutionContext): Promise<boolean> {
    //.......
    //在此处获取请求的路由的权限名称
    const requirePermissions = this.reflector.getAllAndOverride<string[]>(
      'require-permission',
      [context.getHandler(), context.getClass()],
    );

    console.log(requirePermissions);

    //此处做判断 用户是否有权限
    for (const permission of requirePermissions) {
      if (!permissions.some((item) => item.name === permission)) {
        throw new ForbiddenException('你没有没有权限');
      }
    }

    return true;
  }
}
```

### 基于access_token 和 refresh_token实现登录状态无感刷新

在UserController中生成两个token返回，一个access_token，一个refresh_token，过期时间一个 30 分钟，一个 7 天(都可以),登录守卫与之前一样，取出 authorization header 中的 jwt token，这个就是 access_token，对它做校验

前端在调用有登录守卫的接口的时候，token过期则需要在响应拦截器中进行处理，使用refresh_token重新获取新的 access_token，并重新请求接口 还需要在请求拦截器中将access_token 添加到请求头中

```ts
axios.interceptors.request.use((config) => {
  config.headers.Authorization = `Bearer ${localStorage.getItem(
    "access_token"
  )}`;
  return config;
});

axios.interceptors.response.use(
  (response) => {
    return response;
  },
  async (error) => {
    const { data, config } = error.response;
    if (data.statusCode === 401 && !config.url.includes("/user/refresh")) {
      const res = await refreshToken();

      if (res.status) {
        console.log("刷新token成功，重新发起请求", config);

        return axios(config);
      } else {
        alert("登录过期，请重新登录");
        return Promise.reject(res.data);
      }
    } else {
      return error.response;
    }
  }
);
```

但是当需要并发请求，且都需要登录时，就会有并发请求的冲突，前端需要加一个刷新token标识，如果刷新就返回一个promise，并且把它的resolve和方法还有config加到队列里，当refreshToken成功时，修改标识的值，重新发送队列中的请求，并且把结果通过resolve方法.

```ts
let refreshing = false;
const queue: PendingTask[] = [];

axios.interceptors.response.use(
  (response) => {
    return response;
  },
  async (error) => {
    const { data, config } = error.response;

    //此处判断refreshing标识的值，如果为true，则说明正在刷新token，则将当前请求加入队列，等待刷新完成
    if (refreshing) {
      return new Promise((resolve) => {
        queue.push({
          config,
          resolve,
        });
      });
    }
    if (data.statusCode === 401 && !config.url.includes("/user/refresh")) {
      //如果access_token过期，则将refreshing置为true
      refreshing = true;
      const res = await refreshToken();
      //刷新成功，则将开关关闭
      refreshing = false;

      if (res.status === 200) {
        queue.forEach(({ config, resolve }) => {
          resolve(axios(config));
        });

        // 清空队列
        queue.length = 0;

        return axios(config);
      } else {
        alert("登录过期，请重新登录");
        // 清空队列
        queue.length = 0;
        return Promise.reject(res.data);
      }
    } else {
      return error.response;
    }
  }
);
```

### 通过passport策略模式来实现对多种登录方式的封装

首先安装passport 这用到 passport-local 的策略

>npm install --save @nestjs/passport passport
>
>npm install --save passport-local
>
>npm install --save-dev @types/passport-local

在auth在创建local.strategy.ts文件 添加用户名密码认证的策略，在AuthModule中引用

```ts
@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super();
  }

  validate(username: string, password: string) {
    const user = this.authService.validateUser(username, password);
    return user;
  }
}
```

localStrategy从 reqeust 的 body 中取出 username 和 password 交给你去认证，认证过了之后返回 user，它会把 user 放到 request.user 上，如果认证不通过，就抛异常，由 exception filter 处理，在
authService中添加验证用户逻辑，根据用户名密码去校验，查询用户逻辑需要放在用户模块

在需要认证的接口上添加 `@UseGuards(AuthGuard('*'))`

紧接着做Jwt验证，添加 jwt.strategy.ts,在 AuthModule 引用

```ts

//首先要在app.module.ts中引入JwtModule
JwtModel.register({
  //密钥
  secret: 'shiyb',
})

//然后在登录接口返回jwt的token
@UseGuards(AuthGuard('local'))
@Post('login')
async login(@Req() req: Request) {
  console.log(req.user);
  const token = this.jwtService.sign({
    userId: req.user.userId,
    username: req.user.username
  }, {
    expiresIn: '0.5h'
  });

  return {
    token
  }
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      //此处的serectcretOrKey是密钥，要与创建jwtModule的密钥一致
      secretOrKey: 'shiyb',
    });
  }

  async validate(payload: any) {
    return { userId: payload.userId, username: payload.username };
  }
}
```

如果想对 Guard 的流程做一些扩展,比如 jwt 的 Guard，现在需要在每个 controller 上手动应用，通过一个 @IsPublic 的装饰器来标识，如果有 @IsPublic 的装饰器就不需要身份认证，否则就需要  首先生成一个自定义的装饰器,给被装饰对象添加一个 metadata
>nest g decorator is-public --flat --no-spec

```ts
import { SetMetadata } from '@nestjs/common';

export const IS_PUBLIC_KEY = 'isPublic';
export const IsPublic = () => SetMetadata(IS_PUBLIC_KEY, true);

```

需要对`AuthGuard('jwt')`做下扩展,新疆jwtAuthGuard.ts

```ts
import { ExecutionContext, Injectable } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { AuthGuard } from "@nestjs/passport";
import { IS_PUBLIC_KEY } from "src/is-public.decorator";

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(private reflector: Reflector) {
    super();
  }

  canActivate(context: ExecutionContext) {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic) {
      return true;
    }
    return super.canActivate(context);
  }
}

```

在 AppModule 里注册为全局 Guard

```ts
providers: [
  {
    provide: APP_GUARD,
    useClass: JwtAuthGuard
  }
]
```

-1.validate 方法： LocalStrategy 中的 validate 方法是 Passport 策略的核心部分。它负责验证用户的身份，通常是通过检查用户名和密码。如果验证成功，validate 方法返回用户信息。

-2. Passport 处理： 当 validate 方法返回用户信息时，Passport 会将这个用户信息附加到请求对象的 req.user 属性上。这样，在后续的控制器方法中，你可以通过 req.user 访问到这个用户信息

#### 实现github登录

[关于nestJs策略passport网站](https://www.passportjs.org/packages/)

安装GitHub2策略
>npm install --save passport-github2
>
>npm install --save-dev @types/passport-github2

首先要拿到要拿到 client id 和 secret

>github->设置->developer settings->OAuth Apps->new OAuth App

在auth文件夹下创建auth.strategy.ts

```ts
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Profile, Strategy } from 'passport-github2';

@Injectable()
export class GithubStrategy extends PassportStrategy(Strategy, 'github') {
  constructor() {
    super({
      clientID: '此处是上个步骤生成的clientID',
      clientSecret: '此处是上个步骤生成的clientSecret',
      callbackURL: '此处是配置的Authorization callback URL',
      scope: ['public_profile'],
    });
  }

  validate(accessToken: string, refreshToken: string, profile: Profile) {
    return profile;
  }
}
```

#### 实现Google登录

安装相关的possport模块
>npm install --save passport-google-oauth20
>
>npm install --save-dev @types/passport-google-oauth20

获取 client id 和 client secret。[打开 google cloud 的控制台页面](https://console.cloud.google.com/welcome)

### 基于 Redis 实现分布式 session

创建redis服务及模块，模块连接redis服务，

```ts
@Module({
  providers: [
    RedisService,
    {
      provide: 'REDIS_CLIENT',
      async useFactory() {
        const client = createClient({
            socket: {
                host: 'localhost',
                port: 6379
            }
        });
        await client.connect();
        return client;
      }
    }
  ],
  exports: [RedisService]
})
```

在服务里面注入 REDIS_CLIENT 并封转关于hGetAll方法，hSet方法，来设置和读取Redis中的数据

redis 的 hash 有这些方法：

- HSET key field value： 设置指定哈希表 key 中字段 field 的值为 value。
- HGET key field：获取指定哈希表 key 中字段 field 的值。
- HMSET key field1 value1 field2 value2 ...：同时设置多个字段的值到哈希表 key 中。
- HMGET key field1 field2 ...：同时获取多个字段的值从哈希表 key 中。
- HGETALL key：获取哈希表 key 中所有字段和值。
- HDEL key field1 field2 ...：删除哈希表 key 中一个或多个字段。
- HEXISTS key field：检查哈希表 key 中是否存在字段 field。
- HKEYS key：获取哈希表 key 中的所有字段。
- HVALUES key：获取哈希表 key 中所有的值。 -HLEN key：获取哈希表 key 中字段的数量。
- HINCRBY key field increment：将哈希表 key 中字段 field 的值增加 increment。
- HSETNX key field value：只在字段 field 不存在时，设置其值为 value。

然后封装session模块及方法，来设置session和获取session

### Nest内置swagger文档

>npm install --save @nestjs/swagger

在main.ts中配置swagger

```ts
const config = new DocumentBuilder()
    //接口文档标题
    .setTitle('Nestjs-example')
    //接口文档描述
    .setDescription('The API description')
    //接口文档版本
    .setVersion('1.0')
    //接口文档标签
    .addTag('Nestjs-redis-demo')
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);
```

```ts
@ApiOperation({ summary: '接口标题' ,description: '接口描述'})

//描述接口返回数据
@ApiResponse() 
example: { status: HttpStatus.OK, description: 'aaa 成功', type: String }

//query参数的描述
@ApiQuery()
example: { 
  name: 'name', //参数名
  type: String, //参数值类型
  required: true, //是否必须
  description: 'name',//参数描述
  example: '1111', //参数示例值
}

//param参数的描述
@ApiParam()

//body 的描述
@ApiBody()
//可以声明一个Dto类，来描述bady的类型  Dto 是 data transfer object，用于参数的接收。
//声明一个Vo类 可以用于描述返回结果
example:
ccc(@Body('ccc') ccc: CccDto) {
    console.log(ccc);
    const vo = new CccVo();
    vo.aaa = 111;
    vo.bbb = 222;
    return vo;
}

通过 @ApiTags('xxx') 来给接口分组

//有些接口是需要授权才能调用的，需要在main中DocumentBuilder之后添加
.addBasicAuth({
  type: 'http',
  name: 'basic',
  description: '用户名 + 密码'
})
.addCookieAuth('sid', {
  type: 'apiKey',
  name: 'cookie',
  description: '基于 cookie 的认证'
})
.addBearerAuth({
  type: 'http',
  description: '基于 jwt 的认证',
  name: 'bearer'
})

然后在需要授权的接触处添加
@ApiBearerAuth('bearer')
@ApiCookieAuth('cookie')
@ApiBasicAuth('basic')

```

- ApiOperation：声明接口信息
- ApiResponse：声明响应信息，一个接口可以多种响应
- ApiQuery：声明 query 参数信息
- ApiParam：声明 param 参数信息
- ApiBody：声明 body 参数信息，可以省略
- ApiProperty：声明 dto、vo 的属性信息
- ApiPropertyOptional：声明 dto、vo 的属性信息，相当于 required: false 的 ApiProperty
- ApiTags：对接口进行分组
- ApiBearerAuth：通过 jwt 的方式认证，也就是 Authorization: Bearer xxx
- ApiCookieAuth：通过 cookie 的方式认证
- ApiBasicAuth：通过用户名、密码认证，在 header 添加 Authorization: Basic xxx

### 创建公共的Dto 以及如何继承Dto

```ts
import { IntersectionType, PartialType, PickType, OmitType } from '@nestjs/mapped-types';
import { CreateAaaDto } from "./create-aaa.dto";
import { xxxDto } from "./xxx.dto";

//使用PartialType方法来继承类
//它创建了一个新的 class 返回，继承了传入的 class 的属性，和 validation metadata。
export class UpdateAaaDto extends PartialType(CreateAaaDto) {}

//使用PickType方法来继承类 可以只传指定的属性
export class UpdateAaaDto extends PickType(CreateAaaDto, ['age', 'email']) {}
//使用OmitType 从之前的 dto 删除几个字段
export class UpdateAaaDto extends OmitType(CreateAaaDto, ['name', 'hoobies', 'sex']) {}
//PickType 是从中挑选几个，OmitType 是从中去掉几个取剩下的

//可以用 IntersectionTypel来合并两个类
export class UpdateAaaDto extends IntersectionType(CreateAaaDto, xxxDto) {}

//这几个也可以配合使用
export class UpdateAaaDto extends IntersectionType(
  //从CreateAaaDto类中去掉name和age属性 从xxxDto类中去除yyy属性
    PickType(CreateAaaDto, ['name', 'age']), 
    PartialType(OmitType(XxxDto, ['yyy']))
) {}

```

### 序列化Entity  不需要VO对象

要用到 class-transformer 这个包

>npm install --save class-transformer

在不需要返回的 Entity 中添加 @Exclude()

```ts
import { Exclude } from 'class-transformer';
export class User {
    id: number;

    username: string;

    @Exclude()
    password: string;

    email: string;

    constructor(partial: Partial<User>) {
        Object.assign(this, partial);
    }
}
```

然后在controller中方法上添加@UseInterceptors(ClassSerializerInterceptor)

```ts
@UseInterceptors(ClassSerializerInterceptor)
@Get()
findAll() { }
```

装饰器不止@Exclude()，还有@Expose()，@Transform()

`@Expose()` 是添加一个导出的字段，这个字段是只读的  `@Transform()` 是对返回的字段值进行一些转换

```ts
  @Expose()
  get xxx(): string {
      return `${this.username} ${this.email}`;
  }

  @Transform(({value}) => '邮箱是：' + value)
  email: string;
```

swagger的@ApiResponse() 也完全可以用entity代替vo，想要排除的字段加一下@ApiHideProperty()就好了

### Nest中的定时任务以及删除定时任务

#### 三种定时任务

安装定时任务包
>npm install --save @nestjs/schedule

在App.module.ts中引入 `imports: [ScheduleModule.forRoot()]`,创建一个service `nest g service task --flat --no-spec` 通过 @Cron 声明任务执行时间

使用@Cron来执行定时任务

```ts
import { Injectable } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';

@Injectable()
export class TaskService {

  //Nest提供了CronExpression枚举类型，其中包含了一些常用的定时时间
  @Cron(CronExpression.EVERY_5_SECONDS)
  handleCron() {
    //在这里做定时任务
    console.log('task execute');
  }
}
```

还可以使用@Interval 来执行定时任务,以及使用@Timeout 来执行定时任务

```ts
//500ms执行一次
@Interval('task2', 500)
task2() {
    console.log('task2');
}

//3000ms后执行一次
@Timeout('task3', 3000)
task3() {
    console.log('task3');
}

```

#### 清楚定时任务

可以在 AppModule 里注入 SchedulerRegistry，然后在 onApplicationBootstrap 的声明周期里拿到所有的 cronJobs

```ts
export class AppModule implements OnApplicationBootstrap {
  @Inject()
  private schedulerRegistry: SchedulerRegistry;

  onApplicationBootstrap() {
    //清除Cron定时任务
    const crons = this.schedulerRegistry.getCronJobs();
    crons.forEach((item, key) => {
      item.stop();
      this.schedulerRegistry.deleteCronJob(key);
    });

    //清除Interval定时任务
    const intervals = this.schedulerRegistry.getIntervals();
    intervals.forEach(item => {
      const interval = this.schedulerRegistry.getInterval(item);
      clearInterval(interval);
      this.schedulerRegistry.deleteInterval(item);
    })

    //清除Timeout定时任务
    const timeouts = this.schedulerRegistry.getTimeouts();
    timeouts.forEach(item => {
      const timeout = this.schedulerRegistry.getTimeout(item);
      clearTimeout(timeout);
      this.schedulerRegistry.deleteTimeout(item);
    })
  }

}
```

### Nest如何实现事件通信

安装相应的包`npm i --save @nestjs/event-emitter`,然后在App.module.ts中引入 `imports: [EventEmitterModule.forRoot()]`

```ts
EventEmitterModule.forRoot({
  wildcard: true, // 启用通配符
  delimiter: '.',// namespace 和事件名的分隔符，默认为点号，可根据需要修改
})
```

比如在aaa.service.ts中发送事件

```ts
findAll() {
    this.eventEmitter.emit('aaa.find',{
      data: 'xxxx'
    })

    this.eventEmitter.emit('aaa.find2',{
      data: 'xxxx2'
    })
    return `This action returns all aaa`;
}
```

然后在bbb.service.ts中监听事件

```ts
//使用通配符可以调用所有的 aaa. 事件
@OnEvent('aaa.*')
  handleAaaFindEvent(payload) {
    console.log('aaa.find 被调用', payload);
    this.create(new CreateBbbDto());
  }
```
