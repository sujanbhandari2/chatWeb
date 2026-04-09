import { API_PATHS } from '../constants/api.constant';
import { apiAxios } from '../lib/axios';
import { ApiError } from '../lib/api-error';
import type { TranslateResponse, TranscribeResponse } from '../types/chat';
import { apiService } from '../lib/api-service';

export const transcribeSpeechRequest = (
  audio: File | Blob,
  options?: { language?: string; processAgain?: boolean; filename?: string }
): Promise<TranscribeResponse> => {
  const formData = new FormData();
  const name = options?.filename ?? (audio instanceof File ? audio.name : 'audio.webm');
  formData.append('audio', audio, name);
  if (options?.language) {
    formData.append('language', options.language);
  }
  if (options?.processAgain !== undefined) {
    formData.append('processAgain', options.processAgain ? 'true' : 'false');
  }
  return apiAxios
    .post<TranscribeResponse>(API_PATHS.SPEECH.TRANSCRIBE, formData)
    .then((res) => res.data)
    .catch((err) => {
      throw ApiError.fromAxios(err);
    });
};

export const translateTextRequest = (input: {
  text: string;
  targetLanguage: string;
  sourceLanguage?: string;
}): Promise<TranslateResponse> => apiService.post<TranslateResponse>(API_PATHS.SPEECH.TRANSLATE, input);
