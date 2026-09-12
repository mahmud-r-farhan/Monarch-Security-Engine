import React from 'react';
import { Button } from "./ui/button"
import { Input } from "./ui/input"
import { Label } from "./ui/label"
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "./ui/popover"
import { Switch } from "./ui/switch"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "./ui/dropdown-menu"
import { FaFileImport, FaSave, FaCog, FaPlus } from 'react-icons/fa';
import { useTranslation } from 'react-i18next';

export interface HeaderProps {
  onImageUpload: (file: File) => void;
  onExport: () => void;
  isDarkMode: boolean;
  setIsDarkMode: (value: boolean) => void;
  colorFormat: string;
  setColorFormat: (value: string) => void;
  language: string;
  setLanguage: (value: string) => void;
  onNewCanvas: (width: number, height: number) => void;
}

const Header: React.FC<HeaderProps> = ({
  onImageUpload,
  onExport,
  isDarkMode,
  setIsDarkMode,
  colorFormat,
  setColorFormat,
  language,
  setLanguage,
  onNewCanvas
}) => {
  const { t } = useTranslation();

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      onImageUpload(file);
    }
  };

  const handleNewCanvas = () => {
    const width = prompt(t('enterWidth'), '800');
    const height = prompt(t('enterHeight'), '600');
    if (width && height) {
      onNewCanvas(parseInt(width, 10), parseInt(height, 10));
    }
  };

  return (
    <header className="bg-white dark:bg-gray-800 shadow-md p-4">
      <div className="max-w-7xl mx-auto flex justify-between items-center">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">{t('imageEditor')}</h1>
        <div className="flex items-center space-x-4">
          <Popover>
            <PopoverTrigger asChild>
              <Button variant="outline"><FaFileImport className="mr-2" /> {t('import')}</Button>
            </PopoverTrigger>
            <PopoverContent className="w-80">
              <div className="grid gap-4">
                <div className="space-y-2">
                  <h4 className="font-medium leading-none">{t('importImage')}</h4>
                  <p className="text-sm text-muted-foreground">
                    {t('uploadImageDescription')}
                  </p>
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="image">{t('image')}</Label>
                  <Input id="image" type="file" onChange={handleFileChange} accept="image/*" />
                </div>
              </div>
            </PopoverContent>
          </Popover>
          <Button onClick={onExport}><FaSave className="mr-2" /> {t('save')}</Button>
          <Button onClick={handleNewCanvas}><FaPlus className="mr-2" /> {t('newCanvas')}</Button>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline"><FaCog className="mr-2" /> {t('settings')}</Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent className="w-56">
              <DropdownMenuLabel>{t('appearance')}</DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem>
                <div className="flex items-center justify-between w-full">
                  <span>{t('darkMode')}</span>
                  <Switch
                    checked={isDarkMode}
                    onCheckedChange={setIsDarkMode}
                  />
                </div>
              </DropdownMenuItem>
              <DropdownMenuItem>
                <div className="flex items-center justify-between w-full">
                  <span>{t('colorFormat')}</span>
                  <select
                    value={colorFormat}
                    onChange={(e) => setColorFormat(e.target.value)}
                    className="ml-2 p-1 border rounded bg-background text-foreground"
                  >
                    <option value="RGB">RGB</option>
                    <option value="CMYK">CMYK</option>
                    <option value="HSL">HSL</option>
                  </select>
                </div>
              </DropdownMenuItem>
              <DropdownMenuItem>
                <div className="flex items-center justify-between w-full">
                  <span>{t('language')}</span>
                  <select
                    value={language}
                    onChange={(e) => setLanguage(e.target.value)}
                    className="ml-2 p-1 border rounded bg-background text-foreground"
                  >
                    <option value="en">English</option>
                    <option value="es">Español</option>
                    <option value="zh">中文</option>
                    <option value="fr">Français</option>
                    <option value="de">Deutsch</option>
                    <option value="ar">العربية</option>
                  </select>
                </div>
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
    </header>
  );
};

export default Header;
