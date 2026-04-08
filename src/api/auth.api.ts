import { API_PATHS } from '../constants/api.constants';
import { apiService } from '../lib/api-service';
import type { LoginInput, RegisterInput } from '../schemas/auth.schemas';
import type { CreateAccountResponse } from '../types/chat';

export const registerUser = (body: RegisterInput): Promise<CreateAccountResponse> =>
  apiService.post<CreateAccountResponse>(API_PATHS.AUTH.CREATE, body);

export const loginUser = (body: LoginInput): Promise<CreateAccountResponse> =>
  apiService.post<CreateAccountResponse>(API_PATHS.AUTH.LOGIN, body);
