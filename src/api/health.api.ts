import axios from 'axios';
import { API_PATHS } from '../constants/api.constants';
import { ApiError } from '../lib/api-error';
import type { HealthResponse } from '../types/chat';
import { getServerOrigin } from '../utils/runtime-endpoints.utils';

export const getHealth = async (): Promise<HealthResponse> => {
  try {
    const { data } = await axios.get<HealthResponse>(`${getServerOrigin()}${API_PATHS.HEALTH}`);
    return data;
  } catch (e) {
    throw ApiError.fromAxios(e);
  }
};
