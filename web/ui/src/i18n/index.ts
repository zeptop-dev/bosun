import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'
import LanguageDetector from 'i18next-browser-languagedetector'
import zhCN from './zh-CN.json'
import zhTW from './zh-TW.json'
import en from './en.json'
import ja from './ja.json'
import ru from './ru.json'
import ko from './ko.json'

// Languages offered in the header menu; the code is the i18next key.
export const languages: { code: string; label: string }[] = [
  { code: 'zh-CN', label: '简体中文' },
  { code: 'zh-TW', label: '繁體中文' },
  { code: 'en', label: 'English' },
  { code: 'ja', label: '日本語' },
  { code: 'ru', label: 'Русский' },
  { code: 'ko', label: '한국어' },
]

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources: { 'zh-CN': { translation: zhCN }, 'zh-TW': { translation: zhTW }, en: { translation: en }, ja: { translation: ja }, ru: { translation: ru }, ko: { translation: ko } },
    fallbackLng: 'zh-CN',
    supportedLngs: languages.map((l) => l.code),
    interpolation: { escapeValue: false },
    detection: { order: ['localStorage', 'navigator'], caches: ['localStorage'] },
  })

export default i18n
