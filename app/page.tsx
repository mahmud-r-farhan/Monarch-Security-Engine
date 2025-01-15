'use client'

import { useEffect } from 'react';
import ImageEditor from '../components/ImageEditor';
import { Toaster } from 'sonner';
import { I18nextProvider } from 'react-i18next';
import i18n from '../i18n';

export default function Home() {
  useEffect(() => {
    // Initialize i18next here
    i18n.init({
      lng: 'en', // Default language
      fallbackLng: 'en',
      interpolation: {
        escapeValue: false,
      },
    });
  }, []);

  return (
    <I18nextProvider i18n={i18n}>
      <div className="dark:bg-gray-900">
        <ImageEditor />
        <Toaster />
      </div>
    </I18nextProvider>
  );
}

