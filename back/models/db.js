import { Sequelize, DataTypes } from "sequelize";

const sequelize = new Sequelize({
  dialect: "sqlite",
  storage: "./database.sqlite",
  logging: false,
});


// Define Room model
const Room = sequelize.define('Room', {
  roomName: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  hostToken: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  joinerToken: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  nonce: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  encryptedInitKey: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  encryptedDefKey: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  encryptedSecret: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  ongoingChat: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: false
  },
  failedAuth: {
  type: DataTypes.INTEGER,
  allowNull: false,
  defaultValue: 0
}

});

// Define Message model
const Message = sequelize.define('Message', {
  roomName: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  sender: {
    type: DataTypes.ENUM('host', 'joiner'),
    allowNull: false,
  },
  message: {
    type: DataTypes.TEXT,
    allowNull: false,
  },
  order: {
    type: DataTypes.NUMBER,
    allowNull: false,
  },

});

export const initDb = async () => {
  await sequelize.sync({ alter: false });
  console.log("DB sync completed");
};
export { sequelize, Room, Message };