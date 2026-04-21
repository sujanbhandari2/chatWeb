import { useMutation } from '@tanstack/react-query';
import { transcribeSpeechRequest, translateTextRequest } from '../api/speech.api';

export const useTranscribeSpeechMutation = () =>
  useMutation({
    mutationFn: (input: {
      audio: File | Blob;
      options?: { language?: string; processAgain?: boolean; filename?: string };
    }) => transcribeSpeechRequest(input.audio, input.options)
  });

export const useTranslateTextMutation = () =>
  useMutation({
    mutationFn: (input: { text: string; targetLanguage: string; sourceLanguage?: string }) =>
      translateTextRequest(input)
  });
