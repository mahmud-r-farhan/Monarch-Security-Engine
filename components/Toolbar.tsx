import React from 'react';
import { FaCrop, FaArrowsAlt, FaFont, FaPaintBrush, FaLayerGroup, FaAdjust, FaMagic, FaEraser, FaMousePointer } from 'react-icons/fa';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "./ui/tooltip"
import { useTranslation } from 'react-i18next';

const Toolbar = ({ onToolChange, activeTool }) => {
  const { t } = useTranslation();

  const tools = [
    { name: 'select', icon: FaMousePointer },
    { name: 'crop', icon: FaCrop },
    { name: 'move', icon: FaArrowsAlt },
    { name: 'text', icon: FaFont },
    { name: 'draw', icon: FaPaintBrush },
    { name: 'eraser', icon: FaEraser },
    { name: 'layers', icon: FaLayerGroup },
    { name: 'adjust', icon: FaAdjust },
    { name: 'effects', icon: FaMagic },
  ];

  return (
    <TooltipProvider>
      <div id="toolbar" className="w-20 bg-white dark:bg-gray-800 shadow-lg">
        {tools.map((tool) => (
          <Tooltip key={tool.name}>
            <TooltipTrigger asChild>
              <button
                className={`w-full p-4 hover:bg-gray-100 dark:hover:bg-gray-700 focus:outline-none focus:bg-gray-200 dark:focus:bg-gray-600 ${
                  activeTool === tool.name ? 'bg-gray-200 dark:bg-gray-600' : ''
                }`}
                onClick={() => onToolChange(tool.name)}
              >
                <tool.icon className="mx-auto text-gray-700 dark:text-gray-300" />
                <span className="text-xs text-gray-600 dark:text-gray-400">{t(`tools.${tool.name}`)}</span>
              </button>
            </TooltipTrigger>
            <TooltipContent>
              <p>{t(`tools.${tool.name}`)}</p>
            </TooltipContent>
          </Tooltip>
        ))}
      </div>
    </TooltipProvider>
  );
};

export default Toolbar;

