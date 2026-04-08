import axios from 'axios';

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly details?: unknown
  ) {
    super(message);
    this.name = 'ApiError';
  }

  static fromAxios(error: unknown): ApiError {
    if (axios.isAxiosError(error)) {
      const status = error.response?.status ?? 0;
      const data = error.response?.data as { message?: string; details?: unknown } | undefined;
      const message =
        (typeof data?.message === 'string' && data.message) ||
        error.message ||
        error.response?.statusText ||
        'Request failed';
      return new ApiError(message, status, data?.details);
    }
    if (error instanceof Error) {
      return new ApiError(error.message, 0);
    }
    return new ApiError('Request failed', 0);
  }
}
