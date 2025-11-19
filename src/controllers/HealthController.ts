import { JsonController, Get } from 'routing-controllers';
import { Service } from 'typedi';

@Service()
@JsonController('/health')
export class HealthController {
  @Get('/')
  async checkHealth() {
    return {
      status: 'OK'
    };
  }
}
