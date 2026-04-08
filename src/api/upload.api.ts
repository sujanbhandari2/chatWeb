import { API_PATHS } from '../constants/api.constants';
import { apiAxios } from '../lib/axios';
import { ApiError } from '../lib/api-error';
import type { UploadFileResponse } from '../types/chat';

export const uploadFileRequest = (file: File): Promise<UploadFileResponse> => {
  const formData = new FormData();
  formData.append('file', file);
  return apiAxios
    .post<UploadFileResponse>(API_PATHS.UPLOAD, formData)
    .then((res) => res.data)
    .catch((err) => {
      throw ApiError.fromAxios(err);
    });
};
