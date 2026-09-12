import React from 'react';
import { FaCrop, FaArrowsAlt, FaFont, FaPaintBrush, FaLayerGroup, FaAdjust, FaMagic, FaEraser, FaMousePointer, FaUndo, FaRedo } from 'react-icons/fa';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "./ui/tooltip"
import { useTranslation } from 'react-i18next';

export interface ToolbarProps {
  onToolChange: (tool: string) => void;
  activeTool: string;
  onUndo?: () => void;
  onRedo?: () => void;
  canUndo?: boolean;
  canRedo?: boolean;
}

const Toolbar: React.FC<ToolbarProps> = ({
  onToolChange,
  activeTool,
  onUndo,
  onRedo,
  canUndo = false,
  canRedo = false
}) => {
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
      <div id="toolbar" className="w-20 bg-white dark:bg-gray-800 shadow-lg flex flex-col justify-between">
        <div>
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
                  <span className="text-xs text-gray-600 dark:text-gray-400 block mt-1">{t(`tools.${tool.name}`)}</span>
                </button>
              </TooltipTrigger>
              <TooltipContent side="right">
                <p>{t(`tools.${tool.name}`)}</p>
              </TooltipContent>
            </Tooltip>
          ))}
        </div>

        {(onUndo || onRedo) && (
          <div className="border-t border-gray-200 dark:border-gray-700 py-2">
            {onUndo && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <button
                    disabled={!canUndo}
                    className="w-full p-3 hover:bg-gray-100 dark:hover:bg-gray-700 disabled:opacity-40 disabled:hover:bg-transparent"
                    onClick={onUndo}
                  >
                    <FaUndo className="mx-auto text-gray-700 dark:text-gray-300" />
                  </button>
                </TooltipTrigger>
                <TooltipContent side="right">
                  <p>Undo</p>
                </TooltipContent>
              </Tooltip>
            )}
            {onRedo && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <button
                    disabled={!canRedo}
                    className="w-full p-3 hover:bg-gray-100 dark:hover:bg-gray-700 disabled:opacity-40 disabled:hover:bg-transparent"
                    onClick={onRedo}
                  >
                    <FaRedo className="mx-auto text-gray-700 dark:text-gray-300" />
                  </button>
                </TooltipTrigger>
                <TooltipContent side="right">
                  <p>Redo</p>
                </TooltipContent>
              </Tooltip>
            )}
          </div>
        )}
      </div>
    </TooltipProvider>
  );
};

export default Toolbar;
